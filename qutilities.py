from pydecred import helpers
from PyQt5 import QtCore, QtWidgets, QtGui
import time
import traceback
import queue
import re

QT_WHITE = QtGui.QColor("white")
WHITE_PALETTE = QtGui.QPalette(QT_WHITE)
ALIGN_LEFT = QtCore.Qt.AlignLeft
ALIGN_CENTER = QtCore.Qt.AlignCenter
ALIGN_RIGHT = QtCore.Qt.AlignRight
ALIGN_TOP = QtCore.Qt.AlignTop

logger = helpers.ConsoleLogger


class ThreadUtilities:
    """
    Some common utitlities that might be used by a manager
    Designed for multiple inheritance scheme
    """
    threadSafeFunctionSignal = QtCore.pyqtSignal(str, tuple, dict)

    def __init__(self):
        self.threads = []
        self.registeredFuncs = {}
        self.scheduledFuncs = {}
        self.qLoopThread = None
        self.qRunning = False
        self.qKilla = False
        self.inQ = queue.Queue()
        self.scheduleTimer = QtCore.QTimer()
        self.scheduleTimer.setTimerType(QtCore.Qt.PreciseTimer)
        self.scheduleTimer.timeout.connect(self.scheduledFunctionTick)

        self.threadSafeReturnValues = {}
        self.threadSafeFunctionSignal.connect(self.runRegisteredFunction)

        # You can use this technique to enforce thread safety in a function
        self.scheduleFunction = self.makeThreadSafeVersion(self._scheduleFunction)

    def cleanUp(self):
        """
        Perform maintenance for shutdown
        """
        self.qKilla = True
        self.scheduleTimer.stop()

    def registerFunction(self, functionKey, func):
        """
        Registers a function in the registeredFuncs dictionary. 
        Used extensively in the queue loop, where the function should be thread safe, such as a pyqtsignal::emit
        """
        self.registeredFuncs[functionKey] = func

    def qEncode(self, func, *args, **kwargs):
        """
        Encodes a dictionary to submit the given args and kwargs to a queue.queue
        """
        return (func, args, kwargs)

    def startQLoop(self):
        """
        If the qLoop is not running, start it
        """
        if not self.qRunning:
            self.qThread = self.makeThread(self.qLoop, lambda *a: None)

    def qLoop(self):
        """
        Process items in the `managerQ` until its empty. 
        Probably triggered as a callback from an API call, although certainly not limited to that purpose.

        :param res: Result of the call to the API
        :type res: True or StrataError
        """
        self.qRunning = True
        try:
            while True:
                if self.qKilla:
                    break
                try:
                    func, args, kwargs = self.inQ.get(True, 1) # Wait for up to 1 second
                    func(*args, **kwargs)
                    # self.registeredFuncs[item["function.key"]](*item["args"], **item["kwargs"])
                except queue.Empty :
                    continue
                except (TypeError, ValueError) as e:
                    if hasattr(self, logger):
                        self.logger.warning("Error encountered while checking Q: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
        except Exception as e:
            self.qRunning = False
            if hasattr(self, logger):
                self.logger.error("Error encountered in qLoop: %s\n%s" % (repr(e), traceback.print_tb(e.__traceback__)))
            return False
        self.qRunning = False

    def makeThread(self, func, callback=None, *args, **kwargs):
        """
        Create and start a `SmartThread`. 
        A reference to the thread is stored in `self.threads` until it completes

        :param function func: The function to run in the thread
        :param function callback: A function to call when the thread has completed. Any results returned by `func` will be passed as the first positional argument. 
        :param list args: Positional arguments to pass to `func`
        :param dict kwargs: Keyword arguments to pass to `func`
        """
        callback = callback if callback else lambda *a: None
        thread = SmartThread(func, callback, *args, **kwargs)
        thread.start()
        newThreadList = []
        for oldThread in self.threads:
            if not oldThread.isFinished():
                newThreadList.append(oldThread)
        self.threads = newThreadList
        self.threads.append(thread)
        return thread

    def runRegisteredFunction(self, functionKey, args, kwargs):
        """
        Used just for thread safe passing of parameters via pyqtsignal, although not limited to that purpose
        """
        self.threadSafeReturnValues[functionKey] = self.registeredFuncs[functionKey](*args, **kwargs)

    def runThreadSafe(self, function, *args, **kwargs):
        """
        Run a function threadSAfe
        """
        functionKey = function.__name__
        self.registeredFuncs[functionKey] = function
        self.threadSafeFunctionSignal.emit(functionKey, args, kwargs)

    def makeThreadSafeVersion(self, function):
        """
        Return a thread-safe version of a function, using self.threadSafeFunctionSignal.emit
        """
        functionKey = "%s.%i" % (function.__name__, id(function))
        self.registerFunction(functionKey, function)
        return lambda *a, fk=functionKey, **k: self.threadSafeFunctionSignal.emit(fk, a, k)

    def _scheduleFunction(self, functionKey, function, expiration, *args, repeatEvery=None, noForce=False, **kwargs):
        if noForce and functionKey in self.scheduledFuncs:
            return True
        expiration = expiration*1000.
        if repeatEvery:
            repeatEvery = repeatEvery*1000
        self.scheduledFuncs[functionKey] = {
            "function": function,
            "args": args,
            "kwargs": kwargs,
            "repeat.every": repeatEvery,
            "expiration": expiration
        }
        tDelta = expiration - time.time()*1000
        if self.scheduleTimer.isActive() and self.scheduleTimer.remainingTime() < tDelta:
            return True
        self.scheduleTimer.start(tDelta if tDelta > 0 else 1)
        return True

    def cancelFunction(self, functionKey):
        """
        Cancel the function of the given key if it exists
        Will not complain if it does not
        """
        self.scheduledFuncs.pop(functionKey, None)

    def scheduledFunctionTick(self):
        """
        Check all the functions in the dict and run any that are ready
        """
        remainingTime = 1e6  # 100 seconds if not told otherwise
        tNow = time.time()*1000
        for functionKey, funcObj in list(self.scheduledFuncs.items()):
            expiration = funcObj["expiration"]
            tDelta = expiration - tNow
            if tDelta <= 0:
                if funcObj["repeat.every"]:
                    if funcObj["repeat.every"] < remainingTime:
                        remainingTime = funcObj["repeat.every"]
                    funcObj["expiration"] = tNow + funcObj["repeat.every"]
                else:
                    self.scheduledFuncs.pop(functionKey)
                funcObj["function"](*funcObj["args"], **funcObj["kwargs"])
        for k, funcObj in self.scheduledFuncs.items():
            expiration = funcObj["expiration"]
            tDelta = expiration - tNow
            if tDelta <= remainingTime:
                remainingTime = tDelta
        self.scheduleTimer.stop()
        self.scheduleTimer.start(max(0, remainingTime))


class SmartThread(QtCore.QThread):
    def __init__(self, func, callback, *args, qtConnectType=QtCore.Qt.AutoConnection, **kwargs):
        super(SmartThread, self).__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.returns = None
        self.callback = callback
        self.finished.connect(lambda: self.callitback(), type=qtConnectType)

    def run(self):
        self.returns = self.func(*self.args, **self.kwargs)

    def callitback(self):
        self.callback(self.returns)


class QConsole(QtWidgets.QPlainTextEdit):
    def __init__(self, parent, *args, **kwargs):
        super(QConsole, self).__init__(parent)
        self.setStyleSheet("")
        self.args = args
        self.kwargs = kwargs
        self.consoleState = helpers.Generic_class(scrollBottom = True)
        self.setSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.MinimumExpanding)
        # self.console.keyPressEvent = lambda e: self.consoleScrollAction("key.press", e)
        self.document().setMaximumBlockCount(250)
        self.setReadOnly(True)
        self.consoleBar = self.verticalScrollBar()
        self.consoleBar.rangeChanged.connect(lambda mx, mn: self.consoleScrollAction("range.changed", mx, mn))
        self.consoleBar.sliderReleased.connect(lambda: self.consoleScrollAction("mouse.release"))
        self.consoleBar.valueChanged.connect(lambda v: self.consoleScrollAction("value.changed", v))
        f = self.font()
        f.setFamily("Roboto Mono")
        self.setFont(f)
        if "palette" in kwargs:
            self.setPalette(kwargs["palette"])
            kwargs.pop("palette")
        self.setBackgroundVisible(True)
        self.asciiStylePattern = r'((?:\033(?:\[95m|\[94m|\[92m|\[93m|\[91m|\[1m|\[4m|\[0m))+)'
        self.htmlMap = {
            "\x1b[95m" : "color:#6971a7;",
            "\x1b[94m" : "color:#6a9fcf;",
            "\x1b[92m" : "color:#8ae234;",
            "\x1b[93m" : "color:#fce94f;",
            "\x1b[91m" : "color:#ef2d35;",
            "\x1b[1m" : "font-weight:bold;",
            "\x1b[4m" : "text-decoration:underline;"
        }

    def append(self, text):
        """
        Perform a little translation before posting
        """
        matches = re.findall(self.asciiStylePattern, text)
        spanCount = 0
        for match in matches:
            if match == "\x1b[0m":
                text = text.replace("\x1b[0m", "</span>"*spanCount, 1)
                spanCount = 0
            else:
                styles = ""
                for key in self.htmlMap:
                    if key in match:
                        styles += self.htmlMap[key]
                if styles:
                    text = text.replace(match, '<span style="%s">' % styles, 1)
                    spanCount += 1
        return super().appendHtml(text.replace("\n","<br />"))

    def keyPressEvent(self, e):
        super().keyPressEvent(e)
        self.consoleScrollAction(e, *self.args, **self.kwargs)

    def consoleScrollAction(self, action, mn=None, mx=None):
        """
        Parse the action and set appropriate variables
        """
        if action == "range.changed":
            if self.consoleState.scrollBottom:
                self.consoleBar.setSliderPosition(mx)
        if action == "value.changed":
            if mn == self.consoleBar.maximum(): # mn here is the current value, such as returned by sliderPosition
                self.consoleState.scrollBottom = True
            else:
                self.consoleState.scrollBottom = False
        if action == "mouse.release":
            if self.consoleBar.maximum() == self.consoleBar.sliderPosition():
                self.consoleState.scrollBottom = True
            else:
                self.consoleState.scrollBottom = False
        if mn == "key.press":
            if action.key() in (QtCore.Qt.Key_End, QtCore.Qt.Key_Down, QtCore.Qt.Key_PageDown):
                if self.consoleBar.maximum() == self.consoleBar.sliderPosition():
                    self.consoleState.scrollBottom = True
                else:
                    self.consoleState.scrollBottom = False


class QToggle(QtWidgets.QAbstractButton):
    """
    Implementation of a clean looking toggle switch translated from 
    https://stackoverflow.com/a/38102598/1124661
    QAbstractButton::setDisabled to disable
    """
    def __init__(self, parent, slotWidth=None, onColor=None, slotColor=None, switchColor=None, disabledColor=None, callback=None, linkedSetting=None, linkedDict=None):
        super(QToggle, self).__init__(parent)
        self.callback = callback
        self.linkedSetting = linkedSetting
        self.linkedDict = linkedDict
        self.onBrush = QtGui.QBrush(QtGui.QColor(onColor)) if onColor else QtGui.QBrush(QtGui.QColor("#357f30"))
        self.slotBrush = QtGui.QBrush(QtGui.QColor(slotColor)) if slotColor else QtGui.QBrush(QtGui.QColor("#999999"))
        self.switchBrush = self.slotBrush # QtGui.QBrush(QtGui.QColor(switchColor)) if switchColor else QtGui.QBrush(QtGui.QColor("#d5d5d5"))
        self.disabledBrush = QtGui.QBrush(QtGui.QColor(disabledColor)) if disabledColor else QtGui.QBrush(QtGui.QColor("#666666"))
        self.switch = False
        self.opacity = 0
        self.xPos = 8
        self.yPos = 8
        self.slotHeight = 16
        self.slotWidth = slotWidth if slotWidth else 38
        self.setFixedWidth(self.slotWidth)
        self.slotMargin = 3
        #self.track
        self.animation = QtCore.QPropertyAnimation(self, b"pqProp", self)
        self.setCursor(QtCore.Qt.PointingHandCursor)

    def paintEvent(self, e):
        """

        """
        painter = QtGui.QPainter(self)
        painter.setPen(QtCore.Qt.NoPen)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        if self.isEnabled():
            painter.setBrush(self.switchBrush)
            painter.setOpacity(0.6 if self.switch else 0.4)
            painter.drawRoundedRect(QtCore.QRect(self.slotMargin, self.slotMargin, self.slotWidth-2*self.slotMargin, self.height()-2*self.slotMargin), 8.0, 8.0)
            # painter.setBrush(self.switchBrush)
            painter.setOpacity(1.0)
            painter.drawEllipse(QtCore.QRect(self.xPos-self.slotHeight/2, self.yPos-self.slotHeight/2, self.height(), self.height()))
        else:
            painter.setBrush(self.disabledBrush)
            painter.setOpacity(1.0)
            painter.drawRoundedRect(QtCore.QRect(self.slotMargin, self.slotMargin, self.slotWidth-2*self.slotMargin, self.height()-2*self.slotMargin), 8.0, 8.0)
            painter.setOpacity(0.75)
            painter.setBrush(self.slotBrush)
            painter.drawEllipse(QtCore.QRect(self.xPos-self.slotHeight/2, self.yPos-self.slotHeight/2, self.height(), self.height()))

    def mouseReleaseEvent(self, e):
        """
    
        """
        if e.button() == QtCore.Qt.LeftButton:
            self.switch = False if self.switch else True
            self.switchBrush = self.onBrush if self.switch else self.slotBrush
            if self.switch:
                self.animation.setStartValue(self.slotHeight/2)
                self.animation.setEndValue(self.width() - self.slotHeight)
                self.animation.setDuration(120)
                self.animation.start()
            else:
                self.animation.setStartValue(self.xPos)
                self.animation.setEndValue(self.slotHeight/2)
                self.animation.setDuration(120)
                self.animation.start()
            if self.linkedSetting and self.linkedDict:
                self.linkedDict[self.linkedSetting] = self.switch
            if self.callback:
                self.callback(self.switch, self)
        super().mouseReleaseEvent(e)

    def sizeHint(self):
        """
    
        """
        return QtCore.QSize(2 * (self.slotHeight + self.slotMargin), self.slotHeight + 2 * self.slotMargin)

    def setOffset(self, o):
        """
        Setter for QPropertyAnimation
        """
        self.xPos = o
        self.update()

    def getOffset(self):
        """
        Getter for QPropertyAnimation
        """
        return self.xPos

    pqProp = QtCore.pyqtProperty(int, fget=getOffset, fset=setOffset)

    def setToggle(self, toggle):
        """
        set ``switch`` to ``toggle``, and update
        """
        self.switch = toggle
        if self.linkedSetting and self.linkedDict:
            self.linkedDict[self.linkedSetting] = self.switch
        if self.switch:
            self.switchBrush = self.onBrush
            self.xPos = self.width() - self.slotHeight
        else:
            self.switchBrush = self.slotBrush
            self.xPos = self.slotHeight/2
        self.update()


def qLabeledToggle(label, parent, *args, **kwargs):
    wgt, lyt = makeWidget(QtWidgets.QWidget, "vertical", parent)
    toggle = QToggle(parent, *args, **kwargs)
    lyt.addWidget(QtWidgets.QLabel(label, wgt))
    lyt.addWidget(toggle)
    return wgt, toggle


def makeWidget(widgetClass, layoutDirection="vertical", parent=None):
    """
    The simply returns a tuple of (widget, layout), with layout of type specified with layout direction.
    layout's parent will be widget. layout's alignment is set to top-left, and margins are set to 0 on both layout and widget
    
    :param QtWidgets.QAbstractWidget widgetClass: The type of widget to make.
    :param str layoutDirection : optional. default "vertical". One of ("vertical","horizontal","grid"). Determines the type of layout applied to the widget 
    """
    widget = widgetClass(parent)
    widget.setContentsMargins(0, 0, 0, 0)
    if layoutDirection == "horizontal":
        layout = QtWidgets.QHBoxLayout(widget)
    elif layoutDirection == "grid":
        layout = QtWidgets.QGridLayout(widget)
    elif layoutDirection == "vertical":
        layout = QtWidgets.QVBoxLayout(widget)
    else:
        return widget
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setAlignment(ALIGN_TOP | ALIGN_LEFT)
    return widget, layout


def addHoverColor(widget, color):
    """
    Adds a background color on hover to the element
    """
    widget.setAutoFillBackground(True)
    p = widget.palette()
    widget._ogPalette = p
    widget._hoverPalette = QtGui.QPalette(p)
    widget._hoverPalette.setColor(QtGui.QPalette.Window, QtGui.QColor(color))
    widget.enterEvent = lambda e, w=widget: w.setPalette(w._hoverPalette)
    widget.leaveEvent = lambda e, w=widget: w.setPalette(w._ogPalette)
    widget.unHover = lambda w=widget: w.setPalette(w._ogPalette)


def setBackgroundColor(widget, color):
    widget.setAutoFillBackground(True)
    p = widget.palette()
    p.setColor(QtGui.QPalette.Window, QtGui.QColor(color))
    widget.setPalette(p)


def horizontalRule(l=0, t=0, r=0, b=0, color="#aaaaaa", height=2, parent=None):
    """
    Create a horizontal rule with the margins and color

    :param int l: Left margin
    :param int t: Top margin
    :param int r: Right margin
    :param int b: Bottom margin
    :param string color: Hex color, with the hash
    """
    wdgt, lyt = makeWidget(QtWidgets.QWidget, "vertical", parent=parent)
    wdgt.setSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Maximum)
    wdgt.setContentsMargins(l, t, r, b)
    #wdgt.setFixedHeight(t+b+height)
    line = QtWidgets.QFrame()
    line.setSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Maximum)
    line.setFixedHeight(height)
    line.setStyleSheet("background-color:%s;" % color)
    line.setContentsMargins(0, 0, 0, 0)
    lyt.addWidget(line, 1)
    return wdgt


def makeLabel(s, y, a=ALIGN_CENTER):
    lbl = QtWidgets.QLabel(s)
    font = lbl.font()
    font.setPixelSize(y)
    lbl.setFont(font)
    lbl.setAlignment(a)
    return lbl


class QSimpleTable(QtWidgets.QTableWidget):
    def __init__(self, parent, *args, iconStacking=None, singleHeader=False, fontWeight=None, maxHeight=None, **kwargs):
        super(QSimpleTable, self).__init__(parent)
        self.singleHeader = singleHeader
        self.iconStacking = iconStacking if iconStacking else QtWidgets.QStyleOptionViewItem.Left
        self.headerFont = QtWidgets.QTableWidgetItem().font()
        self.maxHeight = maxHeight
        self.headerFont.setPixelSize(14)
        self.headerFont.setWeight(fontWeight if fontWeight else QtGui.QFont.DemiBold)
        self.setWordWrap(False)
        self.setFocusPolicy(QtCore.Qt.NoFocus)
        self.setProperty("table-type","plain")
        self.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().hide()
        self.horizontalHeader().hide()
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        if not maxHeight:
            self.wheelEvent = lambda e: None
        self.setRowCount(1)
        self.resizeSelf()
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        if len(args):
            self.setHeaders(*args)
            self.offset = 1
        else:
            self.offset = 0

    def viewOptions(self):
        """
        This will stack icons and text vertically?
        """
        option = QtWidgets.QTableWidget.viewOptions(self)
        option.decorationAlignment = QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter
        option.decorationPosition = self.iconStacking
        return option

    def setHeaders(self, *headers):
        """Set the headers"""
        self.setColumnCount(len(headers))
        font = self.headerFont
        for i, header in enumerate(headers):
            if header:
                item = QtWidgets.QTableWidgetItem(header)
            else:
                item = QtWidgets.QTableWidgetItem()
            item.setTextAlignment(ALIGN_CENTER)
            item.setFont(font)
            self.setItem(0, i, item)

    def clearTable(self, fromRow=None, resize=True):
        """ Clear all but the header row"""
        startRow = self.offset
        if fromRow:
            fromRow += self.offset # To account for the headers
            if fromRow < self.rowCount():
                startRow = fromRow
            else:
                if resize:
                    self.resizeSelf()
                return
        for i in reversed(range(startRow, self.rowCount())):
            self.removeRow(i)
        if resize:
            self.resizeSelf()

    def insertStuff(self, row, col, text=None, icon=None, rowSpan=1, colSpan=1, alignment=None, font=None, resize=True):
        """
        Insert the widget, offsetting row by 1 to account for the headers
        text could also be an QtGui.QIcon
        """
        actualRow = row+self.offset
        alignment = alignment if alignment else ALIGN_CENTER
        if self.rowCount() < actualRow+rowSpan:
            self.setRowCount(actualRow+rowSpan)
        if self.columnCount() < col+colSpan:
            self.setColumnCount(col+colSpan)
        if self.singleHeader and self.columnCount() < col+1:
            self.setColumnCount(col+1)
            self.setSpan(0, 0, 1, col+1)
        if isinstance(text, str):
            text = QtWidgets.QTableWidgetItem(text)
            text.setTextAlignment(alignment)
        elif not text:
            text = QtWidgets.QTableWidgetItem()
        if isinstance(icon, QtGui.QIcon):
            text.setIcon(icon)
        if isinstance(text, QtWidgets.QWidget):
            self.setCellWidget(actualRow, col, text)
        else:
            if font:
                text.setFont(font)
            self.setItem(actualRow, col, text)
        if rowSpan > 1 or colSpan > 1:
            self.setSpan(actualRow, col, rowSpan, colSpan)
        if resize:
            self.resizeSelf()
        return text

    def getItem(self, row, col):
        """
        Return the item at the given position, offsetting the row by 1 to account for the headers, or None if no item available
        """
        return self.item(row+1, col)

    def resizeSelf(self):
        rows = self.rowCount()
        # scrollBarHeight = self.horizontalScrollBar().height()
        # headerHeight = self.horizontalHeader().height()
        rowTotalHeight = 0
        for i in range(rows):
            rowTotalHeight += self.verticalHeader().sectionSize(i)
        if self.maxHeight and rowTotalHeight > self.maxHeight:
            self.setFixedHeight(self.maxHeight)
            self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        else:
            self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
            self.setFixedHeight(rowTotalHeight)


def clearLayout(layout, delete=False):
    """
    Clears all items from the given layout. Optionally deletes the parent widget

    :param QAbstractLayout layout: Layout to clear
    :param bool delete: Default False. Whether or not to delete the widget as well
    """
    for i in reversed(range(layout.count())): 
        widget = layout.itemAt(i).widget()
        widget.setParent(None)
        if delete:
            widget.deleteLater()


def layoutWidgets(layout):
    """
    Clears all items from the given layout. Optionally deletes the parent widget

    :param QAbstractLayout layout: Layout to clear
    :param bool delete: Default False. Whether or not to delete the widget as well
    """
    for i in range(layout.count()): 
        yield layout.itemAt(i).widget()


QUTILITY_STYLE = """
QPushButton[button-style-class=light]{
    background-color:#90caf9;
    border-radius:3px;
    border-color:#bbbbbb;
    border-width:1px;
    border-style:none;
    color:#333333;
    font-weight:500;
}
QPushButton[button-style-class=light]:hover{
    background-color:#c3fdff;
    border-style:none solid solid none;
}
QPushButton[button-style-class=light]:hover:pressed{
    background-color:#90caf9;
    border-style:none;
}
QPushButton[button-style-class=dark]{
    background-color:#a3bbff;
    border-color:#bbbbbb;
    border-radius:3px;
    border-width:1px;
    border-style:solid;
    color:#222222;
    font-weight:600;
}
QPushButton[button-style-class=dark]:hover{
    background-color:#a3ffa7;
}
QPushButton[button-size-class=tiny]{
    padding: 3px 6px;
    font-size:14px;
}
QPushButton[button-size-class=small]{
    padding: 6px 10px;
    font-size:16px;
}
QPushButton[button-size-class=medium]{
    padding: 8px 12px;
    font-size:18px;
}
QPushButton[button-size-class=large]{
    padding: 10px 12px;
    font-size:20px;
}
QComboBox{
    font-size:18px;
    background-color:white;
    border: 1px solid gray;
    padding-left:10px;
    padding-right:15px;
    font-weight:bold;
}
QComboBox::drop-down {
    border-width: 1px;
    border-color:darkgray;
    border-left-style:solid;
    background-color:transparent;
}
QComboBox::drop-down:hover {
    background-color:#f1fff9;
}
QComboBox::down-arrow {
    width:0;
    height:0;
    border-style:solid;
    border-width:4px;
    border-top-width:7px;
    border-color:white;
    border-top-color:#555555;
    background-color:white;
    position:relative;
    top:3px;
}
"""
