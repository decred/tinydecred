"""
Copyright (c) 2019, Brian Stafford
See LICENSE for detail

PyQt5 utilities.
"""
import re
from tinydecred.util import helpers
from PyQt5 import QtCore, QtWidgets, QtGui

# Some colors,
QT_WHITE = QtGui.QColor("white")
WHITE_PALETTE = QtGui.QPalette(QT_WHITE)

# Alignments,
ALIGN_LEFT = QtCore.Qt.AlignLeft
ALIGN_CENTER = QtCore.Qt.AlignCenter
ALIGN_RIGHT = QtCore.Qt.AlignRight
ALIGN_TOP = QtCore.Qt.AlignTop
ALIGN_BOTTOM = QtCore.Qt.AlignBottom

# Layout directions.
HORIZONTAL = "horizontal"
VERTICAL = "vertical"
GRID = "grid"

# Themes.
LIGHT_THEME = "light"
DARK_THEME = "dark"

STRETCH = "stretch"

PyObj = 'PyQt_PyObject'

class ThreadUtilities(object):
    """
    Utilities for management of SmartThread objects.
    """
    def __init__(self):
        self.threads = []
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

class SmartThread(QtCore.QThread):
    """
    SmartThread is a QThread extension. It adds little, but offers an
    alternative interface for creating the thread and callback handling.
    """
    def __init__(self, func, callback, *args, qtConnectType=QtCore.Qt.AutoConnection, **kwargs):
        """
        Args:
            func (function): The function to run in a separate thread.
            callback (function): A function to receive the return value from 
            `func`. 
            *args: optional positional arguements to pass to `func`.
            qtConnectType: Signal synchronisity. 
            **kwargs: optional keyword arguments to pass to `func`.
        """
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.returns = None
        self.callback = callback
        self.finished.connect(lambda: self.callitback(), type=qtConnectType)

    def run(self):
        """
        QThread method. Runs the func.
        """
        # print("--SmartThread starting with %s" % self.func.__name__)
        self.returns = self.func(*self.args, **self.kwargs)

    def callitback(self):
        """
        QThread Slot connected to the connect Signal. Send the value returned 
        from `func` to the callback function.
        """
        # print("--SmartThread finishing with %s" % self.callback.__name__)
        self.callback(self.returns)


class QConsole(QtWidgets.QPlainTextEdit):
    """
    A widget for displaying console-style monospace output on a dark background.
    """
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
        f.setFamily("RobotoMono-Regular")
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
        self.state = False
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
        QAbstractButton method. Paint the button.
        """
        painter = QtGui.QPainter(self)
        painter.setPen(QtCore.Qt.NoPen)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        if self.isEnabled():
            painter.setBrush(self.switchBrush)
            painter.setOpacity(0.6 if self.state else 0.4)
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
        Toggle the button.
        """
        if e.button() == QtCore.Qt.LeftButton:
            self.state = False if self.state else True
            self.switchBrush = self.onBrush if self.state else self.slotBrush
            if self.state:
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
                self.linkedDict[self.linkedSetting] = self.state
            if self.callback:
                self.callback(self.state, self)
        super().mouseReleaseEvent(e)

    def sizeHint(self):
        """
        Required to be implemented and return the size of the widget.
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
        Set `switch` to `toggle`, and trigger repaint.
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

def makeWidget(widgetClass, layoutDirection="vertical", parent=None):
    """
    The creates a tuple of (widget, layout), with layout of type specified with 
    layout direction.
    layout's parent will be widget. layout's alignment is set to top-left, and 
    margins are set to 0 on both layout and widget
    
    widgetClass (QtWidgets.QAbstractWidget:) The type of widget to make.
    layoutDirection (str): optional. default "vertical". One of 
        ("vertical","horizontal","grid"). Determines the type of layout applied 
        to the widget.
    """
    widget = widgetClass(parent)
    widget.setContentsMargins(0, 0, 0, 0)
    if layoutDirection == HORIZONTAL:
        layout = QtWidgets.QHBoxLayout(widget)
    elif layoutDirection == GRID:
        layout = QtWidgets.QGridLayout(widget)
    elif layoutDirection == VERTICAL:
        layout = QtWidgets.QVBoxLayout(widget)
    else:
        return widget
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setAlignment(ALIGN_TOP | ALIGN_LEFT)
    return widget, layout

def makeSeries(layoutDirection, *widgets, align=None):
    align = align if align else QtCore.Qt.Alignment()
    wgt, lyt = makeWidget(QtWidgets.QWidget, layoutDirection)
    for w in widgets:
        if w == STRETCH:
            lyt.addStretch(1)
        else:
            lyt.addWidget(w, 0, align)
    return wgt, lyt


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
    """
    Setting a background color with a stylesheet can get messy. Use the palette
    when possible.
    """
    widget.setAutoFillBackground(True)
    p = widget.palette()
    p.setColor(QtGui.QPalette.Window, QtGui.QColor(color))
    widget.setPalette(p)

def makeLabel(s, fontSize, a=ALIGN_CENTER, **k):
    """
    Create a QLabel and set the font size and alignment.

    Args:
        s (str): The label text.
        fontSize (int): Pixel size of the label font.
        a (Qt.QAlignment): The text alignment in the label. 
            default QtCore.Qt.AlignCenter
        **k: Additional keyword arguments to pass to setProperties.
    """
    lbl = QtWidgets.QLabel(s)
    setProperties(lbl, fontSize=fontSize, **k)
    lbl.setAlignment(a)
    return lbl

def setProperties(lbl, color=None, fontSize=None, fontFamily=None):
    """
    A few common properties of QLabels. 
    """
    if color:
        palette =  lbl.palette()
        c = QtGui.QColor(color)
        palette.setColor(lbl.backgroundRole(), c)
        palette.setColor(lbl.foregroundRole(), c)
        lbl.setPalette(palette)
    font = lbl.font()
    if fontSize:
        font.setPixelSize(fontSize)
        lbl.setFont(font)
    if fontFamily:
        font.setFamily(fontFamily)
    lbl.setFont(font)

def pad(wgt, t, r, b, l):
    """
    Add padding around the widget by wrapping it in another widget. 
    """
    w, lyt = makeWidget(QtWidgets.QWidget, HORIZONTAL)
    lyt.addWidget(wgt)
    w.setContentsMargins(l, t, r, b)
    return w


class QSimpleTable(QtWidgets.QTableWidget):
    """
    QSimpleTable is a simple table layout with reasonable default settings. 
    """
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
        """
        Clear all but the header row.
        """
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

    Args:
        layout (QAbstractLayout): Layout to clear
        delete (bool): Default False. Whether or not to delete the widget as well
    """
    for i in reversed(range(layout.count())): 
        widget = layout.itemAt(i).widget()
        widget.setParent(None)
        if delete:
            widget.deleteLater()


def layoutWidgets(layout):
    """
    generator to iterate the widgets in a layout
    
    Args:
        layout (QAbstractLayout): Layout to clear
        delete (bool): Default False. Whether or not to delete the widget as well.
    """
    for i in range(layout.count()): 
        yield layout.itemAt(i).widget()

lightThemePalette = QtGui.QPalette()
lightThemePalette.setColor(QtGui.QPalette.Window, QtGui.QColor("#ffffff"))
lightThemePalette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#333333"))
lightThemePalette.setColor(QtGui.QPalette.Base, QtGui.QColor("#ffffff"))
lightThemePalette.setColor(QtGui.QPalette.Text, QtGui.QColor("#333333"))

darkThemePalette = QtGui.QPalette()
darkThemePalette.setColor(QtGui.QPalette.Window, QtGui.QColor("#3f3f3f"))
darkThemePalette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#ededed"))
darkThemePalette.setColor(QtGui.QPalette.Base, QtGui.QColor("#3f3f3f"))
darkThemePalette.setColor(QtGui.QPalette.Text, QtGui.QColor("#ededed"))
darkThemePalette.setColor(QtGui.QPalette.Button, QtGui.QColor("#666666"))
darkThemePalette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("#efd7ec"))
darkThemePalette.hoverColor = QtGui.QColor("#5d5d5d")



QUTILITY_STYLE = """
QPushButton[button-style-class=light]{
    background-color:white;
    border-radius:3px;
    border-color:#777777;
    border-width:1px;
    border-style:solid;
    color:#333333;
    font-weight:500;
}
QPushButton[button-style-class=light]:hover{
    background-color:#efefef;
    color:#111111;
}
QPushButton[button-style-class=light]:hover:pressed{
    background-color:#efffff;
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
QLineEdit {
    padding: 7px;
    font-size: 16px;
    line-height: 34px;
    border: 1px solid #777777;
    border-radius: 2px;
}
QLineEdit:focus {
    border: 1px solid #333333;
    outline: none;
}
"""
