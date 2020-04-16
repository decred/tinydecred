"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details

PyQt5 utilities.
"""

import re

from PyQt5 import QtCore, QtGui, QtWidgets

from decred.util import helpers


log = helpers.getLogger("QUTIL")

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

PyObj = "PyQt_PyObject"


class ThreadUtilities:
    """
    Utilities for management of SmartThread objects.
    """

    def __init__(self):
        self.threads = []

    def makeThread(self, func, callback=None, *args, **kwargs):
        """
        Create and start a `SmartThread`.
        A reference to the thread is stored in `self.threads` until it completes

        Args:
            func (func): The function to run in the thread.
            callback (func): A function to call when the thread has completed.
                Any results returned by `func` will be passed as the first
                positional argument.
            args (tuple): Positional arguments to pass to `func`.
            kwargs (dict): Keyword arguments to pass to `func`.
        """
        callback = callback if callback else lambda *a: None
        thread = SmartThread(func, callback, *args, **kwargs)
        thread.start()
        newThreadList = []
        for oldThread in self.threads:
            if not oldThread.completed:
                newThreadList.append(oldThread)
        self.threads = newThreadList
        self.threads.append(thread)
        return thread


class SmartThread(QtCore.QThread):
    """
    SmartThread is a QThread extension. It adds little, but offers an
    alternative interface for creating the thread and callback handling.
    """

    def __init__(
        self, func, callback, *args, qtConnectType=QtCore.Qt.AutoConnection, **kwargs
    ):
        """
        Args:
            func (func): The function to run in a separate thread.
            callback (func): A function to receive the return value from `func`.
            *args (tuple): optional positional arguements to pass to `func`.
            qtConnectType (type): Signal synchronisity.
            **kwargs (dict): optional keyword arguments to pass to `func`.
        """
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.returns = None
        self.callback = callback
        self.completed = False
        self.finished.connect(self.callitback, type=qtConnectType)

    def run(self):
        """
        QThread method. Runs the func.
        """
        try:
            self.returns = self.func(*self.args, **self.kwargs)
        except Exception as e:
            log.error(f"exception encountered in QThread: {helpers.formatTraceback(e)}")
            self.returns = False

    def callitback(self):
        """
        QThread Slot connected to the connect Signal. Send the value returned
        from `func` to the callback function.
        """
        try:
            self.callback(self.returns)
        finally:
            self.completed = True


class QConsole(QtWidgets.QPlainTextEdit):
    """
    A widget for displaying console-style monospace output on a dark background.
    """

    def __init__(self, parent, *args, **kwargs):
        super(QConsole, self).__init__(parent)
        self.setStyleSheet("")
        self.args = args
        self.kwargs = kwargs
        self.consoleState = helpers.Generic_class(scrollBottom=True)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding,
            QtWidgets.QSizePolicy.MinimumExpanding,
        )
        # self.console.keyPressEvent = lambda e: self.consoleScrollAction(
        #     "key.press", e)
        self.document().setMaximumBlockCount(250)
        self.setReadOnly(True)
        self.consoleBar = self.verticalScrollBar()
        self.consoleBar.rangeChanged.connect(
            lambda mx, mn: self.consoleScrollAction("range.changed", mx, mn)
        )
        self.consoleBar.sliderReleased.connect(
            lambda: self.consoleScrollAction("mouse.release")
        )
        self.consoleBar.valueChanged.connect(
            lambda v: self.consoleScrollAction("value.changed", v)
        )
        f = self.font()
        f.setFamily("RobotoMono-Regular")
        self.setFont(f)
        if "palette" in kwargs:
            self.setPalette(kwargs["palette"])
            kwargs.pop("palette")
        self.setBackgroundVisible(True)
        self.asciiStylePattern = (
            r"((?:\033(?:\[95m|\[94m|\[92m|\[93m|\[91m|\[1m|\[4m|\[0m))+)"
        )
        self.htmlMap = {
            "\x1b[95m": "color:#6971a7;",
            "\x1b[94m": "color:#6a9fcf;",
            "\x1b[92m": "color:#8ae234;",
            "\x1b[93m": "color:#fce94f;",
            "\x1b[91m": "color:#ef2d35;",
            "\x1b[1m": "font-weight:bold;",
            "\x1b[4m": "text-decoration:underline;",
        }

    def append(self, text):
        """
        Perform a little translation before posting.
        """
        matches = re.findall(self.asciiStylePattern, text)
        spanCount = 0
        for match in matches:
            if match == "\x1b[0m":
                text = text.replace("\x1b[0m", "</span>" * spanCount, 1)
                spanCount = 0
            else:
                styles = ""
                for key in self.htmlMap:
                    if key in match:
                        styles += self.htmlMap[key]
                if styles:
                    text = text.replace(match, f'<span style="{styles}">', 1)
                    spanCount += 1
        return super().appendHtml(text.replace("\n", "<br />"))

    def keyPressEvent(self, e):
        super().keyPressEvent(e)
        self.consoleScrollAction(e, *self.args, **self.kwargs)

    def consoleScrollAction(self, action, mn=None, mx=None):
        """
        Parse the action and set appropriate variables.
        """
        if action == "range.changed":
            if self.consoleState.scrollBottom:
                self.consoleBar.setSliderPosition(mx)
        if action == "value.changed":
            # mn is the current value, such as returned by sliderPosition.
            if mn == self.consoleBar.maximum():
                self.consoleState.scrollBottom = True
            else:
                self.consoleState.scrollBottom = False
        if action == "mouse.release":
            if self.consoleBar.maximum() == self.consoleBar.sliderPosition():
                self.consoleState.scrollBottom = True
            else:
                self.consoleState.scrollBottom = False
        if mn == "key.press":
            if action.key() in (
                QtCore.Qt.Key_End,
                QtCore.Qt.Key_Down,
                QtCore.Qt.Key_PageDown,
            ):
                if self.consoleBar.maximum() == self.consoleBar.sliderPosition():
                    self.consoleState.scrollBottom = True
                else:
                    self.consoleState.scrollBottom = False


class Toggle(QtWidgets.QAbstractButton):
    """
    Implementation of a clean looking toggle switch translated from
    https://stackoverflow.com/a/38102598/1124661
    QAbstractButton::setDisabled to disable
    """

    def __init__(
        self, callback,
    ):
        """
        Args:
            callback func(bool): The callback function will receive the current
                state after it is changed due to a click.
        """
        super().__init__()
        self.callback = callback
        self.onBrush = QtGui.QBrush(QtGui.QColor("#569167"))
        self.slotBrush = QtGui.QBrush(QtGui.QColor("#999999"))
        self.switchBrush = self.slotBrush
        self.disabledBrush = QtGui.QBrush(QtGui.QColor("#666666"))
        self.on = False
        self.fullHeight = 18
        self.halfHeight = self.xPos = self.fullHeight / 2
        self.fullWidth = 34
        self.setFixedWidth(self.fullWidth)
        self.slotMargin = 3
        self.slotHeight = self.fullHeight - 2 * self.slotMargin
        self.travel = self.fullWidth - self.fullHeight
        self.slotRect = QtCore.QRect(
            self.slotMargin,
            self.slotMargin,
            self.fullWidth - 2 * self.slotMargin,
            self.slotHeight,
        )
        self.animation = QtCore.QPropertyAnimation(self, b"pqProp", self)
        self.animation.setDuration(120)
        self.setCursor(QtCore.Qt.PointingHandCursor)

    def paintEvent(self, e):
        """
        QAbstractButton method. Paint the button.
        """
        painter = QtGui.QPainter(self)
        painter.setPen(QtCore.Qt.NoPen)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.setBrush(self.switchBrush if self.on else self.disabledBrush)
        painter.setOpacity(0.6)
        painter.drawRoundedRect(
            self.slotRect, self.slotHeight / 2, self.slotHeight / 2,
        )
        painter.setOpacity(1.0)
        painter.drawEllipse(
            QtCore.QRect(self.xPos, 0, self.fullHeight, self.fullHeight,)
        )

    def mouseReleaseEvent(self, e):
        """
        Toggle the button.
        """
        if e.button() == QtCore.Qt.LeftButton:
            self.on = not self.on
            self.switchBrush = self.onBrush if self.on else self.slotBrush
            self.animation.setStartValue(self.xPos)
            self.animation.setEndValue(self.travel if self.on else 0)
            self.animation.start()
            if self.callback:
                self.callback(self.on)
        super().mouseReleaseEvent(e)

    def sizeHint(self):
        """
        Required to be implemented and return the size of the widget.
        """
        return QtCore.QSize(self.fullWidth, self.fullHeight,)

    def setOffset(self, o):
        """
        Setter for QPropertyAnimation.
        """
        self.xPos = o
        self.update()

    def getOffset(self):
        """
        Getter for QPropertyAnimation.
        """
        return self.xPos

    pqProp = QtCore.pyqtProperty(int, fget=getOffset, fset=setOffset)

    def set(self, on):
        """
        Set state to on, and trigger repaint.
        """
        self.on = on
        self.switchBrush = self.onBrush if on else self.slotBrush
        self.xPos = self.travel if on else 0
        self.update()


def makeWidget(widgetClass, layoutDirection=VERTICAL, parent=None):
    """
    Create a tuple of (widget, layout), with layout of type specified with
    layout direction.
    layout's parent will be widget. layout's alignment is set to top-left, and
    margins are set to 0 on both layout and widget.

    Args:
        widgetClass (QtWidgets.QAbstractWidget): The type of widget to make.
        layoutDirection (str): optional. default VERTICAL. One of
            (HORIZONTAL, VERTICAL, GRID). Determines the type of layout
            applied to the widget.
        parent (object): The parent.
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


def makeSeries(layoutDirection, *widgets, align=None, widget=QtWidgets.QWidget):
    align = align if align else QtCore.Qt.Alignment()
    wgt, lyt = makeWidget(widget, layoutDirection)
    for w in widgets:
        if w == STRETCH:
            lyt.addStretch(1)
        else:
            lyt.addWidget(w, 0, align)
    return wgt, lyt


def makeRow(*wgts, **kwargs):
    """
    Creates a widget with a horizontal layout and adds the supplied widgets.

    Args:
        *wgts *list(QWidget): The widgets for the row.
        **kwargs: keyword arguments are passed directly to makeSeries.
    """
    return makeSeries(HORIZONTAL, *wgts, **kwargs)


def makeColumn(*wgts, **kwargs):
    """
    Creates a widget with a vertical layout and adds the supplied widgets.

    Args:
        *wgts *list(QWidget): The widgets for the column.
        **kwargs: keyword arguments are passed directly to makeSeries.
    """
    return makeSeries(VERTICAL, *wgts, **kwargs)


def addHoverColor(widget, color):
    """
    Adds a background color on hover to the element.
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


def addDropShadow(wgt):
    """
    Add a white background and a drop shadow for the given widget.
    """
    effect = QtWidgets.QGraphicsDropShadowEffect()
    effect.setBlurRadius(5)
    effect.setXOffset(0)
    effect.setYOffset(0)
    effect.setColor(QtGui.QColor("#a1a1a1"))
    setBackgroundColor(wgt, "white")
    wgt.setGraphicsEffect(effect)


def makeLabel(s, fontSize, a=ALIGN_CENTER, **k):
    """
    Create a QLabel and set the font size and alignment.

    Args:
        s (str): The label text.
        fontSize (int): Pixel size of the label font.
        a (Qt.QAlignment): The text alignment in the label.
            default QtCore.Qt.AlignCenter
        **k (dict): Additional keyword arguments to pass to setProperties.
    """
    lbl = QtWidgets.QLabel(s)
    setProperties(lbl, fontSize=fontSize, **k)
    lbl.setAlignment(a)
    return lbl


def makeDropdown(choices):
    """
    Create a QComboBox populated with choices.

    Args:
        choices list(str/obj): The choices to display.

    Returns:
        QComboBox: An initiated QComboBox.
    """
    dd = QtWidgets.QComboBox()
    dd.addItems(choices)
    return dd


def setProperties(lbl, color=None, fontSize=None, fontFamily=None, underline=False):
    """
    A few common properties of QLabels.
    """
    if color:
        palette = lbl.palette()
        c = QtGui.QColor(color)
        palette.setColor(lbl.backgroundRole(), c)
        palette.setColor(lbl.foregroundRole(), c)
        lbl.setPalette(palette)
    font = lbl.font()
    if fontSize:
        font.setPixelSize(fontSize)
    if fontFamily:
        font.setFamily(fontFamily)
    if underline:
        font.setUnderline(True)
    lbl.setFont(font)
    return lbl


def pad(wgt, t, r, b, l):
    """
    Add padding around the widget by wrapping it in another widget.
    """
    w, lyt = makeWidget(QtWidgets.QWidget, HORIZONTAL)
    lyt.addWidget(wgt)
    w.setContentsMargins(l, t, r, b)
    return w


def clearLayout(layout, delete=False):
    """
    Clears all items from the given layout. Optionally deletes the parent
    widget.

    Args:
        layout (QAbstractLayout): Layout to clear.
        delete (bool): Default False. Whether or not to delete the widget as
            well.
    """
    for i in reversed(range(layout.count())):
        widget = layout.itemAt(i).widget()
        widget.setParent(None)
        if delete:
            widget.deleteLater()


def layoutWidgets(layout):
    """
    Generator to iterate the widgets in a layout.

    Args:
        layout (QAbstractLayout): Layout to clear.
    """
    for i in range(layout.count()):
        yield layout.itemAt(i).widget()


def _setMouseDown(wgt, e):
    if e.button() == QtCore.Qt.LeftButton:
        wgt._mousedown = True


def _releaseMouse(wgt, e):
    if e.button() == QtCore.Qt.LeftButton and wgt._mousedown:
        wgt._clickcb()
        wgt._mousedown = False


def _mouseMoved(wgt, e):
    """
    When the mouse is moved, check whether the mouse is within the bounds of
    the widget. If not, set _mousedown to False. The user must click and
    release without the mouse leaving the label to trigger the callback.
    """
    if wgt._mousedown is False:
        return
    qSize = wgt.size()
    ePos = e.pos()
    x, y = ePos.x(), ePos.y()
    if x < 0 or y < 0 or x > qSize.width() or y > qSize.height():
        wgt._mousedown = False


def addClickHandler(wgt, cb):
    wgt._mousedown = False
    wgt._clickcb = cb
    wgt.mousePressEvent = lambda e, w=wgt: _setMouseDown(wgt, e)
    wgt.mouseReleaseEvent = lambda e, w=wgt: _releaseMouse(wgt, e)
    wgt.mouseMoveEvent = lambda e, w=wgt: _mouseMoved(wgt, e)


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
    border-color:#a1a1a1;
    border-width:1px;
    border-style:solid;
    color:#333333;
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
}
QPushButton[button-style-class=dark]:hover{
    background-color:#a3ffa7;
}
QPushButton[button-size-class=tiny]{
    padding: 2px 4px;
    font-size:14px;
}
QPushButton[button-size-class=small]{
    padding: 4px 6px;
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
    font-size: 16px;
    background-color: white;
    border: 1px solid gray;
    padding-left: 10px;
    padding-right: 15px;
    font-weight: bold;
}
QComboBox::drop-down {
    border-width: 1px;
    border-color:darkgray;
    border-left-style:solid;
    background-color:transparent;
}
QComboBox QAbstractItemView {
    selection-color: #33aa33;
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
    padding: 4px 6px;
    font-size: 14px;
    line-height: 22px;
    border: 1px solid #a1a1a1;
}
QLineEdit:focus {
    border: 1px solid #333333;
    outline: none;
}
"""
