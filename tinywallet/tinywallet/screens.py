"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, the Decred developers
See LICENSE for detail
"""

import os
import random
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from PyQt5 import QtCore, QtGui, QtSvg, QtWidgets

from decred.dcr import calc, constants as DCR, nets
from decred.dcr.vsp import VotingServiceProvider
from decred.util import chains, helpers
from decred.wallet.wallet import Wallet
from tinywallet.config import DB

from . import config, qutilities as Q, ui


UI_DIR = os.path.dirname(os.path.realpath(__file__))
log = helpers.getLogger("APPUI")
cfg = config.load()

# Some commonly used ui constants.
TINY = ui.TINY
SMALL = ui.SMALL
MEDIUM = ui.MEDIUM
LARGE = ui.LARGE

# A key to identify the screen fade in animation.
FADE_IN_ANIMATION = "fadeinanimation"

formatTraceback = helpers.formatTraceback

app = None


def sprintDcr(atoms, comma=""):
    """
    Helper to format dcr amounts.

    Args:
        atoms (int): Amount of dcr in atoms to convert to coins.
        comma (str): Separator to add to the end of the string.

    returns:
        str: Formatted dcr amount
    """
    return "{:.2f} dcr{}".format(atoms / 1e8, comma)


def sprintAmount(thing):
    """
    Helper to produce functions that format amounts of thing.

    Args:
        thing (str): The thing to stringify amounts for.

    returns:
        func(int, str)str: Function to stringify amounts of thing.
    """
    return lambda n, comma="": "{} {}{}{}".format(
        n, thing, "" if n == 1 else "s", comma
    )


class TinyDialog(QtWidgets.QFrame):
    """
    TinyDialog is a widget for handling Screen instances. This is the primary
    window of the TinyWallet application. It has a fixed (tiny!) size.
    """

    maxWidth = 525
    maxHeight = 375
    targetPadding = 15
    popSig = QtCore.pyqtSignal(Q.PyObj)
    stackSig = QtCore.pyqtSignal(Q.PyObj)
    topMenuHeight = 26
    successSig = QtCore.pyqtSignal(str)
    errorSig = QtCore.pyqtSignal(str)

    def __init__(self, twApp):
        """
        Args:
            twApp (TinyWallet): The TinyWallet application instance.
        """
        super().__init__()
        global app
        app = twApp
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.popSig.connect(self.pop_)
        self.pop = lambda w=None: self.popSig.emit(w)
        self.stackSig.connect(self.stack_)
        self.stack = lambda p: self.stackSig.emit(p)

        # Set the width and height explicitly. Keep it tiny.
        screenGeo = app.qApp.primaryScreen().availableGeometry()
        self.w = (
            self.maxWidth if screenGeo.width() >= self.maxWidth else screenGeo.width()
        )
        self.h = (
            self.maxHeight
            if screenGeo.height() >= self.maxHeight
            else screenGeo.height()
        )
        availPadX = (screenGeo.width() - self.w) / 2
        self.padX = self.targetPadding if availPadX >= self.targetPadding else availPadX
        self.setGeometry(
            screenGeo.x() + screenGeo.width() - self.w - self.padX,
            screenGeo.y() + screenGeo.height() - self.h,
            self.w,
            self.h,
        )

        self.successSig.connect(self.showSuccess_)
        self.showSuccess = lambda s: self.successSig.emit(s)
        self.errorSig.connect(self.showError_)
        self.showError = lambda s: self.errorSig.emit(s)

        self.mainLayout = QtWidgets.QVBoxLayout(self)
        self.setFrameShape(QtWidgets.QFrame.Box)
        self.setLineWidth(1)

        # The TinyDialog is frameless, but a custom menu bar is implemented.
        menuBar, menuLayout = Q.makeWidget(QtWidgets.QWidget, "horizontal")
        self.mainLayout.addWidget(menuBar)
        menuBar.setFixedHeight(TinyDialog.topMenuHeight)

        # A little spinner that it shown while the wallet is locked.
        self.working = Spinner(20, 3, 0)
        self.working.setVisible(False)
        self.working.setFixedSize(20, 20)
        menuLayout.addWidget(Q.pad(self.working, 3, 3, 3, 3), 0, Q.ALIGN_CENTER)
        app.registerSignal(ui.WORKING_SIGNAL, lambda: self.working.setVisible(True))
        app.registerSignal(ui.DONE_SIGNAL, lambda: self.working.setVisible(False))

        # If enabled by a Screen instance, the user can navigate back to the
        # previous screen.
        self.backIcon = SVGWidget("back", w=20, click=self.backClicked)
        menuLayout.addWidget(Q.pad(self.backIcon, 3, 3, 3, 3))

        # If enabled by a Screen instance, the user can navigate directly to
        # the home screen.
        self.homeIcon = SVGWidget("home", w=20, click=self.homeClicked)
        menuLayout.addWidget(Q.pad(self.homeIcon, 3, 3, 3, 3))

        # Separate the left and right sub-menus.
        menuLayout.addStretch(1)

        self.closeIcon = SVGWidget("x", w=20, click=self.closeClicked)
        menuLayout.addWidget(Q.pad(self.closeIcon, 3, 3, 3, 3))

        # Create a layout to hold Screens.
        w, self.layout = Q.makeWidget(QtWidgets.QWidget, "vertical", self)
        self.mainLayout.addWidget(w)

        # Some styling for the callout
        self.msg = None
        self.borderPen = QtGui.QPen()
        self.borderPen.setWidth(1)
        self.msgFont = QtGui.QFont("Roboto", 11)
        self.errorBrush = QtGui.QBrush(QtGui.QColor("#fff1f1"))
        self.successBrush = QtGui.QBrush(QtGui.QColor("#f1fff1"))
        self.bgBrush = self.successBrush
        self.textFlags = (
            QtCore.Qt.TextWordWrap | QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop
        )

    def showEvent(self, e):
        # geo = app.sysTray.geometry()
        # print("sysTray.x: %r" % repr(geo.x()))
        # print("sysTray.y: %r" % repr(geo.y()))
        # print("sysTray.width: %r" % repr(geo.width()))
        # print("sysTray.height: %r" % repr(geo.height()))
        pass

    def closeEvent(self, e):
        self.hide()
        e.ignore()

    def stack_(self, w):
        """
        Add the Screen instance to the stack, making it the displayed screen.
        """
        for wgt in Q.layoutWidgets(self.layout):
            wgt.setVisible(False)
        self.layout.addWidget(w)
        # log.debug("stack setting top screen to %s" % type(w).__name__)
        w.runAnimation(FADE_IN_ANIMATION)
        w.setVisible(True)
        self.setIcons(w)
        self.setVisible(True)
        if hasattr(w, "stacked"):
            w.stacked()

    def pop_(self, screen=None):
        """
        Pop the top screen from the stack. If a Screen instance is provided,
        only pop if that is the top screen.

        Args:
            screen (Screen): optional. The the particular screen to pop.
        """
        widgetList = list(Q.layoutWidgets(self.layout))
        if len(widgetList) < 2:
            return
        popped, top = widgetList[-1], widgetList[-2]
        if screen and popped is not screen:
            return
        popped.setVisible(False)
        self.layout.removeWidget(popped)
        # log.debug("pop setting top screen to %s" % type(top).__name__)
        top.setVisible(True)
        top.runAnimation(FADE_IN_ANIMATION)
        self.setIcons(top)
        self.setIcons(top)
        widgetList = list(Q.layoutWidgets(self.layout))

    def setHomeScreen(self, home):
        """
        Set the home screen, which is the bottom screen of the stack and cannot
        be popped.

        Args:
            home (Screen): The home screen.
        """
        # log.debug("setting home screen")
        for wgt in list(Q.layoutWidgets(self.layout)):
            wgt.setVisible(False)
            self.layout.removeWidget(wgt)
        home.setVisible(True)
        home.runAnimation(FADE_IN_ANIMATION)
        self.layout.addWidget(home)
        if hasattr(home, "inserted"):
            home.inserted()
        self.setIcons(home)

    def setIcons(self, top):
        """
        Set the icons according to the Screen's settings.

        Args:
            top (Screen): The top screen.
        """
        self.backIcon.setVisible(top.isPoppable)
        self.homeIcon.setVisible(top.canGoHome)

    def homeClicked(self):
        """
        The clicked slot for the home icon. Pops all screens down to the home
        screen.
        """
        while self.layout.count() > 1:
            self.pop()

    def closeClicked(self):
        """
        User has clicked close. Since TinyWallet is a system tray application,
        the window and it's application panel icon are hidden, but the
        application does not close.
        """
        self.hide()

    def backClicked(self):
        """
        The clicked slot for the back icon. Pops the top screen.
        """
        self.pop()

    def showError_(self, msg):
        """
        Show an error message with a light red background.

        Args:
            msg (str): The error message.
        """
        self.bgBrush = self.errorBrush
        self.showMessage(msg)

    def showSuccess_(self, msg):
        """
        Show an success message with a light green background.

        Args:
            msg (str): The success message.
        """
        self.bgBrush = self.successBrush
        self.showMessage(msg)

    def showMessage(self, msg):
        """
        Show a message.

        Args:
            msg (str): The message.
        """
        self.msg = msg
        self.update()
        timeout = 5 * 1000
        QtCore.QTimer.singleShot(timeout, lambda s=msg: self.hideMessage(s))

    def hideMessage(self, check):
        if self.msg == check:
            self.msg = None
            self.update()

    def paintEvent(self, e):
        """
        Paint the callout in the appropriate place
        """
        super().paintEvent(e)

        if self.msg:
            painter = QtGui.QPainter(self)
            painter.setPen(self.borderPen)
            painter.setFont(self.msgFont)
            # painter.setBrush(self.bgBrush)

            pad = 5
            fullWidth = self.geometry().width()

            column = QtCore.QRect(0, 0, fullWidth - 4 * pad, 10000)

            textBox = painter.boundingRect(column, self.textFlags, self.msg)

            lrPad = (fullWidth - textBox.width()) / 2 - pad

            outerWidth = textBox.width() + 2 * pad
            outerHeight = textBox.height() + 2 * pad

            w = textBox.width() + 2 * pad
            pTop = TinyDialog.topMenuHeight + pad

            painter.fillRect(lrPad, pTop, outerWidth, outerHeight, self.bgBrush)
            painter.drawRect(lrPad, pTop, outerWidth, outerHeight)
            painter.drawText(
                QtCore.QRect(lrPad + pad, pTop + pad, w, 10000),
                self.textFlags,
                self.msg,
            )


class Screen(QtWidgets.QWidget):
    """
    Screen is all the user sees in the main application window. All UI widgets
    should inherit Screen.
    """

    def __init__(self):
        """
        Args:
            app (TinyWallet): The TinyWallet application instance.
        """
        super().__init__()
        # isPoppable indicates whether this screen can be popped by the user
        # when this screen is displayed.
        self.isPoppable = False
        # canGoHome indicates whether the user can navigate directly to the
        # home page when this screen is displayed.
        self.canGoHome = True
        self.animations = {}

        # The layout the that child will use is actually a 2nd descendent of the
        # primary Screen layout. Stretches are used to center a widget
        # regardless of size.
        vLayout = QtWidgets.QVBoxLayout(self)
        vLayout.addStretch(1)
        hw, hLayout = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        vLayout.addWidget(hw)
        hLayout.addStretch(1)
        self.wgt, self.layout = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        hLayout.addWidget(self.wgt)
        hLayout.addStretch(1)
        vLayout.addStretch(1)

    def runAnimation(self, ani):
        """
        Run an animation if its trigger is registered. By default, no animations
        are attached to the screen.

        Args:
            ani (str): The animation trigger.
        """
        if ani in self.animations:
            return self.animations[ani].start()

    def setFadeIn(self, v):
        """
        Set the screen to use a fade-in animation.

        Args:
            v (bool): If True, run the fade-in animation when its trigger is
                received. False will disable the animation.
        """
        if v:
            effect = QtWidgets.QGraphicsOpacityEffect(self)
            self.animations[FADE_IN_ANIMATION] = a = QtCore.QPropertyAnimation(
                effect, b"opacity"
            )
            a.setDuration(550)
            a.setStartValue(0)
            a.setEndValue(1)
            a.setEasingCurve(QtCore.QEasingCurve.OutQuad)
            self.setGraphicsEffect(effect)
        else:
            self.animations.pop(FADE_IN_ANIMATION, None)


class AccountScreen(Screen):
    """
    The standard home screen for a TinyWallet account.
    """

    def __init__(self, acctMgr, acct, assetScreen):
        """
        Args:
            acctMgr (AccountManager): A Decred account manager.
            acct (Account): A Decred account.
            assetScreen (AssetScreen): The Decred asset screen.
        """
        super().__init__()
        self.wallet = app.wallet
        self.acctMgr = acctMgr
        self.account = acct
        self.assetScreen = assetScreen

        # The TinyDialog won't allow popping of the bottom screen anyway.
        self.isPoppable = False
        self.canGoHome = False
        self.ticketStats = None
        self.balance = None
        self.settingsScreen = AccountSettingsScreen(self.saveName)
        self.stakeScreen = StakingScreen(acct)
        self.wgt.setFixedSize(
            TinyDialog.maxWidth * 0.9,
            TinyDialog.maxHeight * 0.9 - TinyDialog.topMenuHeight,
        )

        # Update the home screen when the balance signal is received.
        app.registerSignal(ui.BALANCE_SIGNAL, self.balanceUpdated)
        app.registerSignal(ui.SYNC_SIGNAL, self.walletSynced)

        # BALANCES

        logo = SVGWidget(DCR.LOGO, h=25)

        self.totalBalance = lbl = ClickyLabel(self.balanceClicked, "0.00")
        Q.setProperties(lbl, fontFamily="Roboto", fontSize=33)
        lbl.setContentsMargins(5, 0, 3, 0)
        unit = Q.makeLabel("DCR", 18, color="#777777")
        unit.setContentsMargins(0, 7, 0, 0)

        self.nameLbl = Q.makeLabel(acct.name, 19, fontFamily="Roboto Medium")
        self.nameLbl.setContentsMargins(0, 0, 10, 0)

        acctBttn = app.getButton(TINY, "accounts")
        acctBttn.clicked.connect(self.toAssetScreen)

        top, _ = Q.makeRow(
            logo, self.totalBalance, unit, Q.STRETCH, self.nameLbl, acctBttn
        )
        self.layout.addWidget(top)

        self.availBalance = Q.makeLabel("", 17)
        self.availBalance.setAlignment(Q.ALIGN_LEFT)
        self.stakedBalance = Q.makeLabel("", 17)
        self.stakedBalance.setAlignment(Q.ALIGN_RIGHT)

        row, _ = Q.makeRow(self.availBalance, Q.STRETCH, self.stakedBalance)
        self.layout.addWidget(row)

        self.layout.addStretch(1)

        # SEND DCR

        wgt, grid = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        self.layout.addWidget(wgt)
        self.addrField = QtWidgets.QLineEdit()
        self.addrField.setFixedWidth(300)
        self.valField = QtWidgets.QLineEdit()
        self.valField.setValidator(QtGui.QDoubleValidator(0, 1e16, 8, wgt))
        send = app.getButton(SMALL, "Send")
        send.setIcon(SVGWidget("send", h=12).icon())
        # spend.clicked.connect(self.spendClicked)
        send.clicked.connect(self.sendClicked)
        grid.addWidget(Q.makeLabel("Send to Address", 14, Q.ALIGN_LEFT), 0, 0)
        grid.addWidget(Q.makeLabel("Amount", 14, Q.ALIGN_LEFT), 0, 1)
        grid.addWidget(self.addrField, 1, 0)
        grid.addWidget(self.valField, 1, 1)
        grid.addWidget(send, 1, 2)

        self.layout.addStretch(1)
        self.layout.addWidget(HorizontalRule())

        # ADDRESS

        addrLbl = Q.makeLabel("Receive Decred to", 16)
        addrLbl.setAlignment(Q.ALIGN_CENTER)

        newAddrBttn = app.getButton(TINY, "new address")
        newAddrBttn.setIcon(SVGWidget("plus", h=9).icon())
        newAddrBttn.clicked.connect(self.newAddressClicked)

        row, lyt = Q.makeRow(addrLbl, Q.STRETCH, newAddrBttn)
        self.address = AddressDisplay("")
        box, lyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        lyt.addWidget(self.address, 0, Q.ALIGN_TOP)
        Q.addDropShadow(box)
        lyt.setContentsMargins(5, 2, 5, 0)
        box.setContentsMargins(5, 5, 5, 5)

        left, _ = Q.makeColumn(Q.STRETCH, row, box)
        left.setContentsMargins(5, 5, 5, 10)
        left.setMaximumWidth(320)

        # OPTIONS

        right, optsLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)

        # Settings
        settings = app.getButton(SMALL, "  Settings ")
        settings.setIcon(SVGWidget("gear", h=14).icon())
        settings.clicked.connect(self.settingsClicked)
        optsLyt.addWidget(settings, Q.ALIGN_LEFT)

        # Open staking window..
        stake = app.getButton(SMALL, "  Staking  ")
        stake.setIcon(SVGWidget("check", w=15).icon())
        stake.clicked.connect(self.openStaking)
        optsLyt.addWidget(stake, Q.ALIGN_RIGHT)

        row, _ = Q.makeRow(left, Q.STRETCH, right)
        row.setContentsMargins(0, 10, 0, 0)
        self.layout.addWidget(row)

    def toAssetScreen(self, e=None):
        """
        Qt slot for "accounts" button clicked signal. Stacks the Decred asset
        screen.
        """
        app.home(self.assetScreen)

    def newAddressClicked(self):
        """
        Generate and display a new address.
        """

        def addr():
            return self.account.nextExternalAddress()

        withUnlockedAccount(self.account, addr, self.setNewAddress)

    def setNewAddress(self, address):
        """
        QThread callback for newAddressClicked. Sets the displayed address.

        Args:
            address (str): The new adddress.
        """
        if address:
            self.address.setText(address)

    def showEvent(self, e):
        """
        When this screen is shown, set the payment address.
        """
        self.address.setText(self.account.currentAddress())

    def balanceClicked(self):
        """
        Show the user a basic balance breakdown.
        """
        log.info("balance clicked")

    def balanceUpdated(self, bal):
        """
        A BALANCE_SIGNAL receiver that updates the displayed balance.

        Args:
            bal (account.Balance): A Decred account Balance.
        """
        self.balance = bal
        self.totalBalance.setText("{0:,.6g}".format(bal.total * 1e-8))

        def dec4(flt):
            return f"{flt * 1e-8:,.4f}"

        stakedRatio = bal.staked / bal.total if bal.total > 0 else 0
        self.availBalance.setText(f"{dec4(bal.available)} spendable")
        self.stakedBalance.setText(
            f"{dec4(bal.staked)} staked ({stakedRatio * 100:.2f}%)"
        )
        self.availBalance.setToolTip(f"{round(bal.available/1e8, 8):.8f}")

    def walletSynced(self):
        """
        Connected to the ui.SYNC_SIGNAL. Remove loading spinner and set ticket
        stats.
        """
        self.ticketStats = self.account.ticketStats()

    def spendClicked(self, e=None):
        """
        Display a form to send funds to an address. A Qt Slot, but any event
        parameter is ignored.
        """
        app.appWindow.stack(self.sendScreen)

    def openStaking(self, e=None):
        """
        Display the staking window.
        """
        app.appWindow.stack(self.stakeScreen)

    def settingsClicked(self, e):
        """
        Display the settings screen.
        """
        app.appWindow.stack(self.settingsScreen)

    def sendClicked(self, e):
        """
        Qt slot for clicked signal from submit button. Send the amount specified
        to the address specified.
        """
        val = float(self.valField.text())
        address = self.addrField.text()
        if not address:
            app.appWindow.showError("address can't be empty")
        if val <= 0:
            app.appWindow.showError("value can't be <= 0")

        log.debug("sending %f to %s" % (val, address))

        def send():
            try:
                return self.account.sendToAddress(
                    int(round(val * 1e8)), address
                )  # raw transaction
            except Exception as e:
                log.error("failed to send: %s" % formatTraceback(e))
            return False

        def sent(res):
            if res:
                self.valField.setText("")
                self.addrField.setText("")
                app.home()
                app.appWindow.showSuccess("sent")
            else:
                app.appWindow.showError("transaction error")

        def confirmed():
            withUnlockedAccount(self.account, send, sent)

        app.confirm(
            f"Are you sure you want to send {val:.8f} to {address}?", confirmed,
        )

    def saveName(self, newName):
        """
        Changes and saves the name of the account.

        Args:
            str: The new account name.
        """
        self.account.name = newName
        self.acctMgr.saveAccount(self.account.idx)
        self.nameLbl.setText(self.account.name)
        self.assetScreen.doButtons()
        app.home()

    def stackAndSync(self):
        """
        Start syncing the account.
        """

        def done(ret):
            app.emitSignal(ui.DONE_SIGNAL)
            app.emitSignal(ui.SYNC_SIGNAL)

        def sync(x):
            if not self.account.isUnlocked():
                return
            app.home(self)
            app.emitSignal(ui.WORKING_SIGNAL)
            app.makeThread(self.account.sync, done)

        unlockAccount(self.account, sync)


class PasswordDialog(Screen):
    """
    PasswordDialog is a simple form for getting a user-supplied password.
    """

    doneSig = QtCore.pyqtSignal()

    def __init__(self):
        """
        Args:
            app (TinyWallet): The TinyWallet application instance.
        """
        super().__init__()
        content, mainLayout = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.layout.addWidget(Q.pad(content, 20, 20, 20, 20))
        mainLayout.setSpacing(10)
        self.isPoppable = True
        self.canGoHome = False

        self.args = tuple()
        self.doneSig.connect(self.done_)

        mainLayout.addWidget(QtWidgets.QLabel("password"))
        pw = self.pwInput = QtWidgets.QLineEdit()
        mainLayout.addWidget(pw)
        pw.setEchoMode(QtWidgets.QLineEdit.Password)
        pw.setMinimumWidth(250)
        pw.returnPressed.connect(self.doneSig.emit)

        # Allow user to toggle plain text display.
        row, lyt = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        mainLayout.addWidget(row)
        toggle = Q.QToggle(self, callback=self.showPwToggled)
        lyt.addWidget(QtWidgets.QLabel("show password"))
        lyt.addWidget(toggle)

    def showEvent(self, e):
        """
        QWidget method. Set the cursor when the screen is stacked.
        """
        self.pwInput.setFocus()

    def hideEvent(self, e):
        """
        QWidget method. Clear the password field when the screen is popped.
        """
        self.pwInput.setText("")

    def showPwToggled(self, state, switch):
        """
        QToggle callback. Set plain text password field display.

        Args:
            state (bool): The toggle switch state.
            switch (QToggle): The toggle switch instance.
        """
        if state:
            self.pwInput.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.pwInput.setEchoMode(QtWidgets.QLineEdit.Password)

    def done_(self):
        callback, args, kwargs = self.args
        callback(self.pwInput.text(), *args, **kwargs)

    def withCallback(self, callback, *args, **kwargs):
        """
        Sets the screens callback function, which will be called when the user
        presses the return key while the password field has focus.

        Args:
            callback (func(str, ...)): A function to receive the users password.
            *args: optional. Positional arguments to pass to the callback. The
                arguments are shifted and the password will be the zeroth
                argument.
            **kwargs: optional. Keyword arguments to pass through to the
                callback.

        Returns:
            The screen itself is returned as a convenience.
        """
        self.args = (callback, args, kwargs)
        return self


class Clicker:
    """
    Clicker add click functionality to any QWidget. Designed for multiple
    inheritance.
    """

    def __init__(self, callback):
        """
        Args:
            callback (function): A function to be called when the Widget is
                clicked. Can be None.
        """
        self.mouseDown = False
        self.callback = callback
        self.setCursor(QtCore.Qt.PointingHandCursor)

    def mousePressEvent(self, e):
        if e.button() == QtCore.Qt.LeftButton:
            self.mouseDown = True

    def mouseReleaseEvent(self, e):
        if e.button() == QtCore.Qt.LeftButton and self.mouseDown and self.callback:
            self.callback()

    def mouseMoveEvent(self, e):
        """
        When the mouse is moved, check whether the mouse is within the bounds of
        the label. If not, set mouseDown to False. The user must click and
        release without the mouse leaving the label to trigger the callback.
        """
        if self.mouseDown is False:
            return
        qSize = self.size()
        ePos = e.pos()
        x, y = ePos.x(), ePos.y()
        if x < 0 or y < 0 or x > qSize.width() or y > qSize.height():
            self.mouseDown = False


class ClickyLabel(Clicker, QtWidgets.QLabel):
    """
    A QLabel with a click callback.
    """

    def __init__(self, callback, *a):
        """
        Args:
            callback (func): A callback function to be called when the label
                is clicked.
            *a: Any additional arguments are passed directly to the parent
                QLabel constructor.
        """
        QtWidgets.QLabel.__init__(self, *a)
        Clicker.__init__(self, callback)


class InitializationScreen(Screen):
    """
    A screen shown when no wallet file is detected. This screen offers options
    for creating a new wallet or loading an existing wallet.
    """

    def __init__(self):
        """
        Args:
            app (TinyWallet): The TinyWallet application instance.
        """
        super().__init__()
        self.canGoHome = False
        self.layout.setSpacing(20)
        lbl = Q.makeLabel("Welcome!", 26, fontFamily="Roboto Medium")
        self.layout.addWidget(lbl)
        self.layout.addWidget(Q.makeLabel("How would you like to begin?", 16))

        # Create a new wallet.
        self.initBttn = app.getButton(SMALL, "create wallet")
        self.layout.addWidget(self.initBttn)
        self.initBttn.clicked.connect(self.initClicked)

        # Load a TinyWallet wallet file.
        self.loadBttn = app.getButton(SMALL, "load wallet")
        self.layout.addWidget(self.loadBttn)
        self.loadBttn.clicked.connect(self.loadClicked)

        # Restore a wallet from mnemonic seed.
        self.restoreBttn = app.getButton(SMALL, "restore from seed")
        self.layout.addWidget(self.restoreBttn)
        self.restoreBttn.clicked.connect(self.restoreClicked)

    def initClicked(self):
        """
        Qt Slot for the new wallet button. Initializes the creation of a new
        wallet.
        """
        app.getPassword(self.initPasswordCallback)

    def initPasswordCallback(self, pw):
        """
        Create a wallet encrypted with the user-supplied password. The wallet
        will be open to the default account, but will not be locked for use.

        Args:
            pw (str): A user supplied password string.
        """
        # either way, pop the password window
        def create():
            try:
                app.dcrdata.connect()
                words, wallet = Wallet.create(app.walletFilename(), pw, cfg.netParams)
                return words, wallet
            except Exception as e:
                log.error("failed to create wallet: %s" % formatTraceback(e))

        app.waitThread(create, self.finishInit)

    def finishInit(self, ret):
        """
        The callback from new wallet creation.
        """
        if ret:
            words, wallet = ret
            app.setWallet(wallet)
            app.showMnemonics(words)
        else:
            app.appWindow.showError("failed to create wallet")

    def loadClicked(self):
        """
        The user has selected the "load from file" option. Prompt for a file
        location and load the wallet.
        """
        fd = QtWidgets.QFileDialog(self, "select wallet file")
        fd.setViewMode(QtWidgets.QFileDialog.Detail)
        qdir = QtCore.QDir
        fd.setFilter(qdir.Dirs | qdir.Files | qdir.NoDotAndDotDot | qdir.Hidden)
        if fd.exec_():
            fileNames = fd.selectedFiles()
            if len(fileNames) != 1:
                log.error("More than 1 file selected for importing")
                raise Exception("More than 1 file selected for importing")
        else:
            raise Exception("no file selected")
        walletPath = fileNames[0]
        log.debug("loading wallet from %r" % walletPath)
        if walletPath == "":
            app.appWindow.showError("no file selected")
            return
        elif not os.path.isfile(walletPath):
            log.error("no file found at %s" % walletPath)
            app.showMessaage("file error. try again")
            return

        destination = app.walletFilename()
        helpers.moveFile(walletPath, destination)
        app.initialize()

    def restoreClicked(self):
        """
        User has selected to generate a wallet from a mnemonic seed.
        """
        restoreScreen = MnemonicRestorer()
        app.appWindow.stack(restoreScreen)


class AssetScreen(Screen):
    """
    AssetScreen is screen for choosing one account out of many, or changing
    asset-level settings.
    """

    def __init__(self):
        super().__init__()
        self.isPoppable = False
        self.canGoHome = False
        self.wgt.setFixedSize(
            TinyDialog.maxWidth * 0.9,
            TinyDialog.maxHeight * 0.9 - TinyDialog.topMenuHeight,
        )
        self.accountScreens = {}
        self.settingsScreen = AssetSettingsScreen()

        logo = SVGWidget(DCR.LOGO, h=25)
        lbl = Q.makeLabel("Decred", 25, fontFamily="Roboto Medium")
        gear = SVGWidget("gear", h=20, click=self.gearClicked)
        # Gear icon will lead to an asset settings screen. Hide for now.
        # gear.setVisible(False)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, logo, lbl, Q.STRETCH, gear,)
        self.layout.addWidget(wgt)

        header = Q.makeLabel("Select an account", 20)
        header.setContentsMargins(0, 15, 0, 5)
        header.setAlignment(Q.ALIGN_LEFT)
        self.layout.addWidget(header)

        wgt, self.accountsList = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        self.layout.addWidget(wgt)
        self.acctMgr = app.wallet.accountManager("dcr", app.blockchainSignals)

        self.newAcctScreen = NewAccountScreen(self.acctMgr, self.doButtons)
        self.doButtons()

    def doButtons(self, idx=None):
        """
        Create buttons for account selection.

        Args:
            idx (int): optional. An account index. If set, that account screen
                will be displayed.
        """
        Q.clearLayout(self.accountsList)
        cols = 3

        def rowCol(i):
            return i // cols, i % cols

        def acctSelector(idx):
            def asel():
                self.accountSelected(idx)

            return asel

        for i, acct in enumerate(self.acctMgr.listAccounts()):
            # Text needs to be added after setting layout direction.
            selector = AccountSelector(acct)
            selector.clicked.connect(acctSelector(i))
            row, col = rowCol(i)
            self.accountsList.addWidget(selector, row, col, 1, Q.ALIGN_LEFT)

        for j in range(min(cols, i + 1)):
            self.accountsList.setColumnStretch(j, 1)

        newAcctBttn = app.getButton(SMALL, "add new account")
        newAcctBttn.setIcon(SVGWidget("plus", h=20).icon())
        newAcctBttn.setIconSize(QtCore.QSize(10, 10))
        newAcctBttn.clicked.connect(self.stackNew)
        row, col = rowCol(i + 1)
        self.accountsList.addWidget(newAcctBttn, row, col, 1, Q.ALIGN_LEFT)

        if idx is not None:
            self.accountSelected(idx)

    def accountSelected(self, idx):
        """
        Connected to the account button clicked signal. Stacks the account
        screen, creating it if necessary.

        Args:
            idx (int): The BIP-0044 account index.
        """
        acctScreen = self.accountScreens.get(idx, None)

        if not acctScreen:
            acct = self.acctMgr.account(idx)
            acctScreen = AccountScreen(self.acctMgr, acct, self)
            self.accountScreens[idx] = acctScreen

        acctScreen.stackAndSync()

    def stackNew(self, e=None):
        """
        Stack the account creation screen.
        """
        app.appWindow.stack(self.newAcctScreen)

    def gearClicked(self, e=None):
        """
        Qt slot for a clicked signal on the gear icon.
        """
        app.appWindow.stack(self.settingsScreen)


class AssetSettingsScreen(Screen):
    """A screen to adjust asset-specific settings."""

    def __init__(self):
        super().__init__()
        self.canGoHome = True
        self.isPoppable = True

        self.blockchain = chains.chain("dcr")

        self.wgt.setFixedSize(
            TinyDialog.maxWidth * 0.9,
            TinyDialog.maxHeight * 0.9 - TinyDialog.topMenuHeight,
        )

        gear = SVGWidget("gear", h=20)
        lbl = Q.makeLabel("Decred Settings", 22)
        wgt, _ = Q.makeRow(gear, lbl, Q.STRETCH)
        self.layout.addWidget(wgt)

        self.layout.addStretch(1)

        wgt, grid = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        self.layout.addWidget(wgt)
        grid.setColumnStretch(0, 1)
        row = 0
        grid.addWidget(Q.makeLabel("Dcrdata URL", 14, Q.ALIGN_LEFT), row, 0)
        row += 1
        self.dcrdataField = QtWidgets.QLineEdit(app.settings[DB.dcrdata].decode())
        grid.addWidget(self.dcrdataField, row, 0)
        bttn = app.getButton(SMALL, "change")
        bttn.clicked.connect(self.dcrdataChangeClicked)
        grid.addWidget(bttn, row, 1)

        self.layout.addStretch(1)

    def dcrdataChangeClicked(self, e=None):
        """
        Qt slot connected to dcrdata URL submission button clicked signal.
        Changes the dcrdata server.
        """

        url = self.dcrdataField.text()
        parsedURL = urlsplit(url)
        if not parsedURL.scheme or not parsedURL.netloc:
            app.appWindow.showError("invalid URL")
            return

        def runChangeDcrdata():
            try:
                self.blockchain.changeServer(url)
                app.settings[DB.dcrdata] = url.encode()
                return True
            except Exception as e:
                app.appWindow.showError("change failed")
                log.error(f"error changing dcrdata: {e}")

        def doneChangeDcrdata(res):
            if not res:
                return
            app.appWindow.pop(self)
            log.info(f"dcrdata URL changed to {url}")
            app.appWindow.showSuccess("dcrdata changed")

        app.waitThread(runChangeDcrdata, doneChangeDcrdata)


class AccountSelector(QtWidgets.QPushButton):
    """
    AccountSelector is a button with a locked/unlocked icon that is used to open
    a specific account.
    """

    def __init__(self, acct):
        """
        Args:
            acct (Account): A Decred account.
        """
        super().__init__()
        self.account = acct
        dim = 11
        self.lockedIcon = SVGWidget("locked", h=dim).grab()
        self.unlockedIcon = SVGWidget("unlocked", h=dim).grab()
        self.src = QtCore.QRectF(0, 0, dim, dim)
        self.setProperty("button-style-class", Q.LIGHT_THEME)
        self.setProperty("button-size-class", SMALL)
        self.setText(acct.name)
        self.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))

    def paintEvent(self, e):
        """
        Paint the lock icon. This is an overloaded PyQt method.
        """
        super().paintEvent(e)
        painter = QtGui.QPainter(self)
        painter.setRenderHints(QtGui.QPainter.HighQualityAntialiasing)
        rect = self.contentsRect()
        dim = 11
        pad = 4
        x = rect.width() - dim - pad
        y = (rect.height() / 2) - (dim / 2)
        pic = self.unlockedIcon if self.account.isUnlocked() else self.lockedIcon
        painter.drawPixmap(QtCore.QRectF(x, y, dim, dim), pic, self.src)


class AccountSettingsScreen(Screen):
    """
    Account settings screen.
    """

    def __init__(self, saveName):
        """
        Args:
            saveName (function): A callback function to be called after the user
                submits a new account name.
        """
        super().__init__()
        self.canGoHome = True
        self.isPoppable = True
        self.wgt.setFixedSize(
            TinyDialog.maxWidth * 0.9,
            TinyDialog.maxHeight * 0.9 - TinyDialog.topMenuHeight,
        )
        self.saveName = saveName

        gear = SVGWidget("gear", h=20)
        lbl = Q.makeLabel("Account Settings", 22)
        wgt, _ = Q.makeRow(gear, lbl, Q.STRETCH)
        self.layout.addWidget(wgt)

        self.layout.addStretch(1)

        # ACCOUNT NAME

        wgt, grid = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        self.layout.addWidget(wgt)
        row = 0
        grid.addWidget(Q.makeLabel("Change account name", 14, Q.ALIGN_LEFT), row, 0)
        row += 1
        self.nameField = QtWidgets.QLineEdit()
        self.nameField.setFixedWidth(200)
        grid.addWidget(self.nameField, row, 0)
        bttn = app.getButton(SMALL, "submit")
        bttn.setMaximumWidth(120)
        bttn.clicked.connect(self.nameChangeClicked)
        grid.addWidget(bttn, row, 1)

        self.layout.addStretch(1)

    def nameChangeClicked(self, e):
        """
        Qt slot for nameField.clicked signal.
        """
        newName = self.nameField.text()
        if not newName:
            app.appWindow.showError("empty name not allowed")
            return
        self.nameField.setText("")
        self.saveName(newName)


class NewAccountScreen(Screen):
    """
    A screen that displays a form to create a new account.
    """

    def __init__(self, acctMgr, refresh):
        """
        Args:
            acctMgr (AccountManager): A Decred account manager.
            refresh (function): A function to be called when a new account is
                added.
        """
        super().__init__()
        self.canGoHome = True
        self.isPoppable = True
        self.acctMgr = acctMgr
        self.refresh = refresh
        lbl = Q.makeLabel("Name your new account", 16)
        self.layout.addWidget(lbl)
        self.nameField = QtWidgets.QLineEdit()
        self.nameField.setFixedWidth(200)
        self.layout.addWidget(self.nameField)
        bttn = app.getButton(SMALL, "create account")
        bttn.clicked.connect(self.createAccount)
        self.layout.addWidget(bttn)

    def createAccount(self, e=None):
        """
        Qt slot for "create account" button's connect signal. Create a new
        account.
        """
        name = self.nameField.text()
        if not name:
            app.appWindow.showError("must provide name")

        def doneCreateAcct(acct):
            if not acct:
                return
            self.refresh(acct.idx)

        def runCreateAcct(cryptoKey):
            try:
                acct = self.acctMgr.addAccount(cryptoKey, name)
                acct.unlock(cryptoKey)
                return acct
            except Exception as e:
                log.error(
                    "exception encountered while adding account: %s"
                    % formatTraceback(e)
                )

        def createAcctPW(pw):
            try:
                cryptoKey = app.wallet.cryptoKey(pw)
                app.waitThread(runCreateAcct, doneCreateAcct, cryptoKey)
            except Exception as e:
                log.warning(
                    "exception encountered while decoding wallet key: %s"
                    % formatTraceback(e)
                )
                app.appWindow.showError("error")

        app.waiting()
        app.getPassword(createAcctPW)


class WaitingScreen(Screen):
    """
    Waiting screen displays a Spinner.
    """

    def __init__(self):
        super().__init__()
        self.isPoppable = False
        self.canGoHome = False
        self.spinner = Spinner(60)
        self.layout.addWidget(self.spinner)


class MnemonicScreen(Screen):
    """
    Display the mnemonic seed from wallet creation.
    """

    def __init__(self, words):
        """
        Args:
            words list(str): The mnemonic seed.
        """
        super().__init__()
        self.isPoppable = True
        self.canGoHome = True
        self.wgt.setMaximumWidth(320)
        self.layout.setSpacing(10)

        # Some instructions for the user. It is critical that they copy the seed
        # now, as it can't be regenerated.
        self.lbl = Q.makeLabel(
            "Copy these words carefully and keep them somewhere secure. "
            "You will not have this chance again.",
            16,
        )
        self.lbl.setWordWrap(True)
        self.layout.addWidget(self.lbl)

        # Create a label to hold the actual seed.
        lbl = QtWidgets.QLabel(" ".join(words))
        Q.setProperties(lbl, fontSize=15)
        lbl.setMaximumWidth(500)
        lbl.setStyleSheet("QLabel{border: 1px solid #777777; padding: 10px;}")
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
        )
        row, lyt = Q.makeWidget(QtWidgets.QWidget, "horizontal")
        self.layout.addWidget(row)
        lyt.addStretch(1)
        lyt.addWidget(lbl)
        lyt.addStretch(1)

        # A button that must be clicked to pop the screen.
        button = app.getButton(
            SMALL, "all done", tracked=False
        )  # the mnemonic screen is not persistent. Don't track this button.
        self.layout.addWidget(button)
        button.clicked.connect(self.clearAndClose)

    def clearAndClose(self, e):
        """
        Pop this screen.
        """
        self.lbl.setText("")
        app.appWindow.pop(self)


class MnemonicRestorer(Screen):
    """
    A screen with a simple form for entering a mnemnic seed from which to
    generate a wallet.
    """

    def __init__(self):
        super().__init__()
        self.isPoppable = True
        self.canGoHome = False
        self.wgt.setMaximumWidth(320)
        self.layout.setSpacing(10)

        # Some instructions for the user.
        self.lbl = Q.makeLabel(
            "Enter your mnemonic seed here. Separate words with whitespace.", 18
        )
        self.lbl.setWordWrap(True)
        self.layout.addWidget(self.lbl)

        # A field to enter the seed words.
        self.edit = edit = QtWidgets.QTextEdit()
        edit.setAcceptRichText(False)
        edit.setMaximumWidth(300)
        edit.setFixedHeight(200)
        edit.setStyleSheet("QLabel{border: 1px solid #777777; padding: 10px;}")
        # edit.setTextInteractionFlags(
        #     QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard)
        row, lyt = Q.makeWidget(QtWidgets.QWidget, "horizontal")
        row.setContentsMargins(2, 2, 2, 2)
        self.layout.addWidget(row)
        lyt.addStretch(1)
        lyt.addWidget(edit)
        lyt.addStretch(1)

        # The user must click the button to submit.
        button = app.getButton(
            SMALL, "OK", tracked=False
        )  # the mnemonic screen is not persistent. Don't track this button.
        self.layout.addWidget(button)
        button.clicked.connect(self.tryWords)

    def showEvent(self, e):
        """
        QWidget method. Sets the focus in the QTextEdit.
        """
        self.edit.setFocus()

    def tryWords(self, e):
        """
        Qt Slot for the submit button clicked signal. Attempt to create a
        wallet with the provided words.
        """
        words = self.edit.toPlainText().strip().split()

        def finish(ret):
            if ret is None:
                app.appWindow.showError("failed to create wallet")
                return
            wallet = ret
            app.setWallet(wallet)
            app.home(app.assetScreen)

        def create(pw):
            try:
                app.dcrdata.connect()
                wallet = Wallet.createFromMnemonic(
                    words, app.walletFilename(), pw, cfg.netParams,
                )
                return wallet
            except Exception as e:
                log.error("failed to create wallet: %s" % formatTraceback(e))

        def withpw(pw):
            app.waitThread(create, finish, pw)

        app.getPassword(withpw)


class StakingScreen(Screen):
    """
    A screen with a form to purchase tickets.
    """

    def __init__(self, acct):
        """
        Args:
            acct (Account): A Decred account.
        """
        super().__init__()
        self.isPoppable = True
        self.canGoHome = True
        self.account = acct
        self.layout.setSpacing(20)
        self.poolScreen = PoolScreen(acct, self.poolAuthed)
        self.accountScreen = PoolAccountScreen(acct, self.poolScreen)

        self.agendasScreen = AgendasScreen(acct)
        self.statsScreen = StakeStatsScreen(acct)
        self.balance = None
        self.wgt.setContentsMargins(5, 5, 5, 5)
        self.wgt.setMinimumWidth(400)
        self.blockchain = chains.chain("dcr")
        self.revocableTicketsCount = 0

        # Register for signals.
        app.registerSignal(ui.BALANCE_SIGNAL, self.balanceSet)

        # ticket price is a single row reading `Ticket Price: XX.YY DCR`.
        lbl = Q.makeLabel("Ticket Price: ", 16)
        self.lastPrice = None
        self.lastPriceStamp = 0
        self.ticketPrice = Q.makeLabel("--.--", 24, fontFamily="Roboto Bold")
        unit = Q.makeLabel("DCR", 16)
        priceWgt, _ = Q.makeRow(lbl, self.ticketPrice, unit)
        self.layout.addWidget(priceWgt)

        # Current holdings is a single row that reads `Currently staking X
        # tickets worth YY.ZZ DCR`
        lbl = Q.makeLabel("Currently staking", 14)
        self.ticketCount = Q.makeLabel("", 18, fontFamily="Roboto Bold")
        lbl2 = Q.makeLabel("tickets worth", 14)
        self.ticketValue = Q.makeLabel("", 18, fontFamily="Roboto Bold")
        unit = Q.makeLabel("DCR", 14)
        wgt, _ = Q.makeSeries(
            Q.HORIZONTAL, lbl, self.ticketCount, lbl2, self.ticketValue, unit
        )
        self.layout.addWidget(wgt)

        # A button to view agendas and choose how to vote.
        btn = app.getButton(TINY, "voting")
        btn.clicked.connect(self.stackAgendas)
        agendasWgt, _ = Q.makeSeries(Q.HORIZONTAL, btn)

        # A button to view network and ticket stats.
        btn = app.getButton(TINY, "stats")
        btn.clicked.connect(lambda: app.appWindow.stack(self.statsScreen))

        statsWgt, _ = Q.makeSeries(Q.HORIZONTAL, agendasWgt, btn)

        # A button to revoke expired and missed tickets.
        revokeBtn = app.getButton(TINY, "")
        revokeBtn.clicked.connect(self.revokeTickets)
        votingWgt, _ = Q.makeRow(agendasWgt, revokeBtn)
        self.revokeBtn = revokeBtn
        revokeBtn.clicked.connect(self.revokeTickets)
        votingWgt, _ = Q.makeSeries(Q.HORIZONTAL, agendasWgt, statsWgt, revokeBtn)
        self.layout.addWidget(votingWgt)

        # Hide revoke button unless we have revokable tickets.
        revokeBtn.hide()
        app.registerSignal(ui.SYNC_SIGNAL, self.checkRevocable)

        # Affordability. A row that reads `You can afford X tickets`
        lbl = Q.makeLabel("You can afford ", 14)
        self.affordLbl = Q.makeLabel(" ", 17, fontFamily="Roboto Bold")
        lbl2 = Q.makeLabel("tickets", 14)
        affordWgt, _ = Q.makeRow(lbl, self.affordLbl, lbl2)
        affordWgt.setContentsMargins(0, 0, 0, 30)
        self.layout.addWidget(affordWgt)

        # The actual purchase form. A box with a drop shadow that contains a
        # single row reading `Purchase [ ] tickets     [Buy Now]`.
        lbl = Q.makeLabel("Purchase", 16)
        lbl2 = Q.makeLabel("tickets", 16)
        lbl2.setContentsMargins(0, 0, 30, 0)
        qty = self.ticketQty = QtWidgets.QLineEdit()
        qty.setValidator(QtGui.QRegExpValidator(QtCore.QRegExp("[0-9]*")))
        qty.setFixedWidth(40)
        font = lbl2.font()
        font.setPixelSize(18)
        qty.setFont(font)
        qty.returnPressed.connect(self.buyClicked)
        btn = app.getButton(SMALL, "Buy Now")
        btn.clicked.connect(self.buyClicked)
        purchaseWgt, lyt = Q.makeRow(lbl, qty, lbl2, Q.STRETCH, btn)
        lyt.setContentsMargins(10, 10, 10, 10)
        Q.addDropShadow(purchaseWgt)
        self.layout.addWidget(purchaseWgt)

        # Navigate to account screen, to choose or add a different VSP account.
        self.currentPool = Q.makeLabel("", 15)
        lbl2 = ClickyLabel(lambda: app.appWindow.stack(self.accountScreen), "change")
        Q.setProperties(lbl2, underline=True, fontSize=15)
        Q.addHoverColor(lbl2, "#f5ffff")
        wgt, lyt = Q.makeRow(self.currentPool, Q.STRETCH, lbl2)
        lyt.setContentsMargins(0, 10, 0, 0)
        self.layout.addWidget(wgt)

        self.sync()

    def stacked(self):
        """
        stacked is called on screens when stacked by the TinyDialog.
        """
        acct = self.account
        if not acct.hasPool():
            app.appWindow.pop(self)
            app.appWindow.stack(self.poolScreen)

    def stackAgendas(self):
        """
        Stack the agendas screen.
        """
        acct = self.account
        if not acct:
            log.error("no account selected")
            app.appWindow.showError("cannot vote: no account")
            return
        pools = acct.stakePools
        if len(pools) == 0:
            app.appWindow.showError("cannot vote: no pools")
            return
        if len(self.agendasScreen.agendas) == 0:
            app.appWindow.showError("cannot vote: could not fetch agendas")
            return
        if not self.agendasScreen.voteSet:
            app.appWindow.showError("cannot vote: pool not synced")
            return
        app.appWindow.stack(self.agendasScreen)

    def checkRevocable(self):
        """
        On SYNC_SIGNAL signal hide or show revoke button based on wether or not
        we have revocable tickets.
        """
        acct = self.account
        n = self.revocableTicketsCount
        for utxo in acct.utxos.values():
            if utxo.isRevocableTicket():
                n += 1
        if n > 0:
            self.revokeBtn.setText("revoke {}".format(sprintAmount("ticket")(n)))
            self.revokeBtn.show()
        else:
            self.revokeBtn.hide()

    def revokeTickets(self):
        """
        Revoke all revocable tickets.
        """

        def revoke(wallet):
            try:
                app.emitSignal(ui.WORKING_SIGNAL)
                self.account.revokeTickets()
                return True
            except Exception as e:
                log.error("revoke tickets error: %s" % formatTraceback(e))
                return False
            app.emitSignal(ui.DONE_SIGNAL)

        withUnlockedAccount(self.account, revoke, self.revoked)

    def revoked(self, success):
        """
        revokeTickets callback. Prints success or failure to the screen.
        """
        if success:
            n = self.revocableTicketsCount
            plural = ""
            if n > 0:
                if n > 1:
                    plural = "s"
                app.appWindow.showSuccess("revoked {} ticket{}".format(n, plural))
                self.revocableTicketsCount = 0
            self.revokeBtn.hide()
        else:
            app.appWindow.showError("revoke tickets finished with error")

    def setStats(self):
        """
        Get the current ticket stats and update the display.
        """
        acct = self.account
        stats = acct.ticketStats()
        self.ticketCount.setText(str(stats.count))
        self.ticketValue.setText("%.2f" % (stats.value / 1e8))
        stakePool = acct.stakePool()
        if stakePool:
            self.currentPool.setText(stakePool.url)

    def sync(self):
        """
        Connected to the BLOCKCHAIN_CONNECTED signal. Updates the current
        ticket price.
        """

        def getTicketPrice(blockchain):
            try:
                return blockchain.stakeDiff() / 1e8
            except Exception as e:
                log.error("error fetching ticket price: %s" % e)
                return False

        app.makeThread(getTicketPrice, self.ticketPriceCB, self.blockchain)

    def ticketPriceCB(self, ticketPrice):
        """
        Sets the current ticket price and updates the display.

        Args:
            ticketPrice (float): The ticket price, in DCR.
        """
        if not ticketPrice:
            return
        self.lastPrice = ticketPrice
        self.lastPriceStamp = int(time.time())
        self.ticketPrice.setText("%.2f" % ticketPrice)
        self.ticketPrice.setToolTip("%.8f" % ticketPrice)
        self.setBuyStats()

    def balanceSet(self, balance):
        """
        Connected to the BALANCE_SIGNAL signal. Sets the balance and updates
        the display.

        Args:
            balance (account.Balance): The current account balance.
        """
        self.balance = balance
        self.setBuyStats()
        self.setStats()

    def setBuyStats(self):
        """
        Update the display of the current affordability stats.
        """
        if self.balance and self.lastPrice:
            self.affordLbl.setText(
                str(int(self.balance.available / 1e8 / self.lastPrice))
            )

    def buyClicked(self, e=None):
        """
        Connected to the "Buy Now" button clicked signal. Initializes the ticket
        purchase routine.
        """
        qtyStr = self.ticketQty.text()
        if not qtyStr or qtyStr == "":
            app.appWindow.showError("can't purchase zero tickets")
            return
        qty = int(qtyStr)
        if qty > self.balance.available / 1e8 / self.lastPrice:
            app.appWindow.showError("can't afford %d tickets" % qty)

        def done(txs):
            if txs is None:
                return
            app.home()

        def do():
            return self.buyTickets(qty)

        def step():
            withUnlockedAccount(self.account, do, done)

        app.confirm(
            "Are you sure you want to purchase %d ticket(s) for %.2f DCR? "
            "Once purchased, these funds will be locked"
            " until your tickets vote or expire." % (qty, qty * self.lastPrice),
            step,
        )

    def buyTickets(self, qty):
        """
        The second step in the sequence for a ticket purchase. Defer the hard
        work to the open Account.

        Args:
            wallet (Wallet): The open wallet.
            qty (int): The number of tickets to purchase.

        Returns:
            list(msgtx.MsgTx): The purchased tickets.
        """
        txs = self.account.purchaseTickets(qty, self.lastPrice)
        if txs:
            app.home()
        app.appWindow.showSuccess("bought %s tickets" % qty)
        return txs

    def poolAuthed(self, res):
        """
        The callback from the PoolScreen when a pool is added. If res evaluates
        True, the pool was successfully authorized.
        """
        if not res:
            # The pool screen handles error notifications.
            app.home()
        window = app.appWindow
        window.pop(self.poolScreen)
        window.stack(self)


class LiveTicketsScreen(Screen):
    """
    A screen that shows network and ticket stats.
    """

    def __init__(self):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__()
        self.isPoppable = True
        self.canGoHome = True

        self.wgt.setMinimumWidth(400)
        self.wgt.setMinimumHeight(225)

        self.liveTickets = {}

        # Network statistics
        lbl = Q.makeLabel("Live Tickets", 18)
        self.layout.addWidget(lbl, 0, Q.ALIGN_LEFT)

        # List of live tickets. Click to open dcrdata in browser.
        wgt = self.ticketsWgt = QtWidgets.QListWidget()
        wgt.itemClicked.connect(self.onTicketItemClicked)
        self.layout.addWidget(wgt, 0, Q.ALIGN_LEFT)

    def onTicketItemClicked(self, item):
        """
        Open clicked tickets in dcrdata in the user's browser.
        """
        hostname = nets.normalizeName(cfg.netParams.Name)
        utxo = self.liveTickets[item.text()[:8]]
        url = urlunsplit(("https", f"{hostname}.dcrdata.org", f"/{utxo.txid}", "", ""))
        helpers.openInBrowser(url)

    def addItems(self, liveTickets):
        """
        Add tickets to the live list.

        Args:
            liveTickets(dict[txid]UTXO): List of live tickets.
        """
        self.liveTickets = liveTickets
        self.ticketsWgt.clear()
        self.ticketsWgt.addItems(
            [
                "{}... {}".format(
                    k,
                    " @ height {}".format(utxo.height)
                    if utxo.height > -1
                    else " unconfirmed",
                )
                for k, utxo in self.liveTickets.items()
            ]
        )


class StakeStatsScreen(Screen):
    """
    A screen that shows network and ticket stats.
    """

    def __init__(self, acct):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__()
        self.isPoppable = True
        self.canGoHome = True

        self.account = acct
        self.liveTicketsScreen = LiveTicketsScreen()

        self.updatingLock = threading.Lock()

        # live and immature tickets, viewable on dcrdata
        self.liveTickets = {}

        # keep track of last update and update if past LIFE
        self.lastUpdated = time.time()
        self.LIFE = DCR.HOUR

        # Update stats on initial sync or if spent tickets have been updated.
        app.registerSignal(ui.SYNC_SIGNAL, self.setStats)
        app.registerSignal(ui.SPENT_TICKETS_SIGNAL, self.setStats)

        self.wgt.setMinimumWidth(400)
        self.wgt.setMinimumHeight(225)

        # header and a button to show live tickets
        lbl = Q.makeLabel("Staking", 18)
        self.liveTicketsListBtn = btn = app.getButton(TINY, "live tickets")
        btn.clicked.connect(lambda: app.appWindow.stack(self.liveTicketsScreen))
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, Q.STRETCH, btn)
        self.layout.addWidget(wgt)
        btn.hide()

        # network statistics
        lbl = Q.makeLabel("Network", 16)
        self.layout.addWidget(lbl, 0, Q.ALIGN_LEFT)

        lbl = Q.makeLabel("current height: ", 14)
        h = self.blkHeight = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, h)
        self.layout.addWidget(wgt)

        # ticket prices
        lbl = Q.makeLabel("current price: ", 14)
        lbl2 = Q.makeLabel("next price: ", 14)
        qty = self.stakeDiff = Q.makeLabel("", 14)
        qty2 = self.nextStakeDiff = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2)
        self.layout.addWidget(wgt)

        # ticket pool and next blocks left in stake window
        lbl = Q.makeLabel("ticket pool: ", 14)
        lbl2 = Q.makeLabel("next diff in: ", 14)
        qty = self.networkTickets = Q.makeLabel("", 14)
        qty2 = self.blocksLeft = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2)
        self.layout.addWidget(wgt)

        # reward and total staked
        lbl = Q.makeLabel("reward: ", 14)
        lbl2 = Q.makeLabel("total staked: ", 14)
        qty = self.stakebase = Q.makeLabel("", 14)
        qty2 = self.networkValue = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2)
        self.layout.addWidget(wgt)

        # Lifetime user statistics
        lbl = Q.makeLabel("Lifetime", 16)
        self.layout.addWidget(lbl, 0, Q.ALIGN_LEFT)

        # A row of lifetime rewards and fees.
        lbl = Q.makeLabel("rewards: ", 14)
        lbl2 = Q.makeLabel("pool fees: ", 14)
        lbl3 = Q.makeLabel("tx fees: ", 14)
        qty = self.allStakebases = Q.makeLabel("", 14)
        qty2 = self.allPoolFees = Q.makeLabel("", 14)
        qty3 = self.allTxFees = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2, lbl3, qty3)
        self.layout.addWidget(wgt)

        # A row of lifetime profits.
        lbl = Q.makeLabel("net profit: ", 14)
        qty = self.netProfit = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty)
        self.layout.addWidget(wgt)

        # A row of voted and revoked ticket numbers.
        lbl = Q.makeLabel("voted: ", 14)
        lbl2 = Q.makeLabel("revoked: ", 14)
        qty = self.votedCount = Q.makeLabel("", 14)
        qty2 = self.revokedCount = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2)
        self.layout.addWidget(wgt)

        # Current staking statistics
        lbl = Q.makeLabel("Current", 16)
        self.layout.addWidget(lbl, 0, Q.ALIGN_LEFT)

        # A row of immature, live, and revocable ticket numbers.
        lbl = Q.makeLabel("immature: ", 14)
        lbl2 = Q.makeLabel("live: ", 14)
        lbl3 = Q.makeLabel("revocable: ", 14)
        qty = self.immatureCount = Q.makeLabel("", 14)
        qty2 = self.liveCount = Q.makeLabel("", 14)
        qty3 = self.revocableCount = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2, lbl3, qty3)
        self.layout.addWidget(wgt)

        # total staked and a button to show a list of live tickets
        lbl = Q.makeLabel("total staked:", 14)
        amt = self.ticketValue = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, amt)
        self.layout.addWidget(wgt)

    def stacked(self):
        """
        Update on stacking if necessary.
        """
        if time.time() > self.lastUpdated + self.LIFE:
            self.setStats()

    def setStats(self):
        """
        Set stats on SPENT_TICKETS_SIGNAL, SYNC_SIGNAL, or if stacking and
        self.LIFE has expired.
        """
        if self.updatingLock.locked():
            return
        self.updatingLock.acquire()
        self.liveTicketsListBtn.hide()

        def setstats():
            app.emitSignal(ui.WORKING_SIGNAL)
            self.setStatsNetwork()
            self.setStatsLifetime()
            self.setStatsCurrent()
            app.emitSignal(ui.DONE_SIGNAL)
            self.lastUpdated = time.time()
            self.updatingLock.release()

        app.makeThread(setstats)

    def setStatsNetwork(self):
        """
        Set network statistics.
        """
        blockchain = app.dcrdata

        r = sprintDcr
        t = sprintAmount("ticket")
        b = sprintAmount("block")

        tpinfo = blockchain.ticketPoolInfo()
        self.blkHeight.setText(str(tpinfo.height))
        self.networkTickets.setText(t(tpinfo.size, ", "))
        self.networkValue.setText("{:.2f} dcr".format(tpinfo.value))
        blocksLeft = calc.blksLeftStakeWindow(cfg.netParams, tpinfo.height)
        self.blocksLeft.setText(b(blocksLeft))
        cache = calc.SubsidyCache(cfg.netParams)
        self.stakebase.setText(r(cache.calcStakeVoteSubsidy(tpinfo.height), ", "))

        stakeDiff = blockchain.stakeDiff()
        self.stakeDiff.setText(r(stakeDiff, ", "))

        nextStakeDiff = blockchain.nextStakeDiff()
        self.nextStakeDiff.setText(r(nextStakeDiff))

    def setStatsLifetime(self):
        """
        Set lifetime statistics.
        """

        r = sprintDcr

        allStakebases, allPoolFees, allTxFees = self.account.calcTicketProfits()
        self.allStakebases.setText(r(allStakebases, ", "))
        self.allPoolFees.setText(r(allPoolFees, ", "))
        self.allTxFees.setText(r(allTxFees))
        netProfit = allStakebases - allPoolFees - allTxFees
        self.netProfit.setText(r(netProfit))

    def setStatsCurrent(self):
        """
        Set current, unspent tickets. Populate live ticket list.
        """

        r = sprintDcr
        t = sprintAmount("ticket")

        unSpent, voted, revoked, _ = self.account.sortedTickets()
        self.votedCount.setText(t(len(voted), ", "))
        self.revokedCount.setText(t(len(revoked)))
        live = 0
        immature = 0
        revocable = 0
        unconfirmed = 0
        self.liveTickets = {"{}".format(k[:8]): v for k, v in unSpent.items()}
        for ticket in self.liveTickets.values():
            if ticket.isLiveTicket():
                live += 1
            elif ticket.isImmatureTicket():
                immature += 1
            elif ticket.isRevocableTicket():
                revocable += 1
            else:
                unconfirmed += 1
        self.immatureCount.setText(t(immature + unconfirmed, ", "))
        self.liveCount.setText(t(live, ", "))
        self.revocableCount.setText(t(revocable))
        if len(self.liveTickets) > 0:
            self.liveTicketsScreen.addItems(self.liveTickets)
            self.liveTicketsListBtn.show()
        stats = self.account.ticketStats()
        self.ticketValue.setText(r(stats.value))


class PoolScreen(Screen):
    """
    A screen for adding new VSPs.
    """

    def __init__(self, acct, callback):
        """
        Args:
            acct (Account): A Decred account.
            callback (function): A function to call when a pool is succesfully
                validated.
        """
        super().__init__()
        self.isPoppable = True
        self.canGoHome = True
        self.account = acct
        self.callback = callback
        self.pools = []
        self.poolIdx = -1
        self.wgt.setMinimumWidth(400)
        self.wgt.setContentsMargins(15, 0, 15, 0)

        # After the header, there are two rows that make up the form. The first
        # row is a QLineEdit and a button that takes the pool URL. The second
        # row is a slightly larger QLineEdit for the API key.
        lbl = Q.makeLabel("Add a voting service provider", 16)
        wgt, _ = Q.makeRow(lbl, Q.STRETCH)
        self.layout.addWidget(wgt)
        self.poolIp = edit = QtWidgets.QLineEdit()
        edit.setPlaceholderText("e.g. https://anothervsp.com")
        edit.returnPressed.connect(self.authPool)
        btn = app.getButton(SMALL, "Add")
        btn.clicked.connect(self.authPool)
        wgt, _ = Q.makeRow(self.poolIp, btn)
        wgt.setContentsMargins(0, 0, 0, 5)
        self.layout.addWidget(wgt)
        self.keyIp = edit = QtWidgets.QLineEdit()
        edit.setPlaceholderText("API key")
        self.keyIp.setContentsMargins(0, 0, 0, 30)
        self.layout.addWidget(edit)
        edit.returnPressed.connect(self.authPool)

        # A separate header for the pick-a-VSP section.
        l = Q.ALIGN_LEFT
        lbl = Q.makeLabel("Don't have a VSP yet? Heres one.", 15, a=l)
        self.layout.addWidget(lbl)

        # Display info for a randomly chosen pool (with some filtering), and a
        # couple of links to aid in selecting a VSP..
        self.poolUrl = Q.makeLabel("", 16, a=l, fontFamily="Roboto Medium")
        self.poolUrl.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        Q.addClickHandler(self.poolUrl, self.poolClicked)
        self.poolLink = Q.makeLabel("visit", 14, a=l)
        self.poolLink.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        Q.addHoverColor(self.poolLink, "#f3f9ff")
        Q.addClickHandler(self.poolLink, self.linkClicked)

        scoreLbl = Q.makeLabel("score:", 14)
        self.score = Q.makeLabel("", 14)
        feeLbl = Q.makeLabel("fee:", 14)
        self.fee = Q.makeLabel("", 14)
        usersLbl = Q.makeLabel("users:", 14)
        self.users = Q.makeLabel("", 14)
        stats, _ = Q.makeSeries(
            Q.HORIZONTAL,
            self.poolLink,
            Q.STRETCH,
            scoreLbl,
            self.score,
            Q.STRETCH,
            feeLbl,
            self.fee,
            Q.STRETCH,
            usersLbl,
            self.users,
        )
        poolWgt, lyt = Q.makeColumn(self.poolUrl, stats)
        lyt.setContentsMargins(10, 10, 10, 10)
        lyt.setSpacing(10)
        Q.addDropShadow(poolWgt)
        Q.addHoverColor(poolWgt, "#f5ffff")
        self.layout.addWidget(poolWgt)

        # A button to select a different pool and a link to the master list on
        # decred.org.
        btn1 = app.getButton(TINY, "show another")
        btn1.clicked.connect(self.randomizePool)
        btn2 = app.getButton(TINY, "see all")
        btn2.clicked.connect(self.showAll)
        wgt, _ = Q.makeRow(btn1, Q.STRETCH, btn2)
        self.layout.addWidget(wgt)

        self.sync()

    def sync(self):
        """
        Get the current master list of VSPs from decred.org.
        """
        netParams = app.dcrdata.netParams

        def getvsp():
            try:
                return VotingServiceProvider.providers(netParams)
            except Exception as e:
                log.error("error retrieving stake pools: %s" % e)
                return False

        app.makeThread(getvsp, self.setPools)

    def setPools(self, pools):
        """
        Cache the list of stake pools from decred.org, and pick one to display.

        Args:
            pools (list(dict)): The freshly-decoded-from-JSON stake pools.
        """
        if not pools:
            return
        self.pools = pools
        tNow = int(time.time())
        # Only save pools updated within the last day, but allow bad pools for
        # testing.
        # TODO: Have 3 tinydecred network constants retreivable through cfg
        #   instead of checking the network config's Name attribute.
        if cfg.netParams.Name == "mainnet":
            self.pools = [
                p
                for p in pools
                if tNow - p["LastUpdated"] < 86400 and self.scorePool(p) > 95
            ]
        self.randomizePool()

    def randomizePool(self, e=None):
        """
        Randomly select a pool from the best performing half, where performance
        is based purely on voting record, e.g. voted/(voted+missed). The sorting
        and some initial filtering was already performed in setPools.
        """
        pools = self.pools
        count = len(pools)
        if count == 0:
            log.warning("no stake pools returned from server")
        lastIdx = self.poolIdx
        if count == 1:
            self.poolIdx = 0
        else:
            # pick random elements until the index changes
            while self.poolIdx == lastIdx:
                self.poolIdx = random.randint(0, count - 1)
        pool = pools[self.poolIdx]
        self.poolUrl.setText(pool["URL"])
        self.score.setText("%.1f%%" % self.scorePool(pool))
        self.fee.setText("%.1f%%" % pool["PoolFees"])
        self.users.setText(str(pool["UserCountActive"]))

    def scorePool(self, pool):
        """
        Get the pools performance score, as a float percentage.
        """
        if pool["Voted"] == 0:
            return 0
        return pool["Voted"] / (pool["Voted"] + pool["Missed"]) * 100

    def authPool(self):
        """
        Connected to the "Add" button clicked signal. Attempts to authorize the
        user-specified pool and API key.
        """
        url = self.poolIp.text()
        err = app.appWindow.showError
        if not url:
            err("empty address")
            return
        apiKey = self.keyIp.text()
        if not apiKey:
            err("empty API key")
            return
        url = urlsplit(url)
        if not url.scheme or not url.netloc:
            err("invalid URL")
            return
        # Remove any path.
        url = urlunsplit((url.scheme, url.netloc, "/", "", ""))
        pool = VotingServiceProvider(url, apiKey, cfg.netParams.Name)

        def registerPool():
            try:
                addr = self.account.votingAddress().string()
                pool.authorize(addr)
                app.appWindow.showSuccess("pool authorized")
                self.account.setNewPool(pool)
                # Notify that vote data should be updated.
                app.emitSignal(ui.PURCHASEINFO_SIGNAL)
                return True
            except Exception as e:
                err("pool authorization failed")
                log.error("pool registration error: %s" % formatTraceback(e))
                return False

        withUnlockedAccount(self.account, registerPool, self.callback)

    def showAll(self, e=None):
        """
        Connected to the "see all" button clicked signal. Open the fu
        decred.org VSP list in the browser.
        """
        helpers.openInBrowser("https://decred.org/vsp/")

    def linkClicked(self):
        """
        Callback from the clicked signal on the pool URL QLabel. Opens the
        pool's homepage in the users browser.
        """
        helpers.openInBrowser(self.poolUrl.text())

    def poolClicked(self):
        """
        Callback from the clicked signal on the try-this-pool widget. Sets the
        URL in the QLineEdit.
        """
        self.poolIp.setText(self.poolUrl.text())


class AgendasScreen(Screen):
    """
    A screen that lists current agendas and allows for vote configuration.
    """

    def __init__(self, acct):
        """
        Args:
            acct (Account): A Decred account.
        """
        super().__init__()
        self.isPoppable = True
        self.canGoHome = True
        self.account = acct

        # Currently shown agenda dropdowns are saved here.
        self.dropdowns = []
        self.agendas = []
        self.pages = []
        self.page = 0
        self.voteSet = False
        self.blockchain = chains.chain("dcr")

        app.registerSignal(ui.PURCHASEINFO_SIGNAL, self.setVote)

        self.wgt.setMinimumWidth(400)
        self.wgt.setMinimumHeight(225)

        lbl = Q.makeLabel("Agendas", 18)
        self.layout.addWidget(lbl, 0, Q.ALIGN_LEFT)

        wgt, self.agendasLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.agendasLyt.setSpacing(10)
        self.agendasLyt.setContentsMargins(5, 5, 5, 5)
        self.layout.addWidget(wgt)

        prevPg = app.getButton(TINY, "back")
        prevPg.clicked.connect(self.pageBack)
        nextPg = app.getButton(TINY, "next")
        nextPg.clicked.connect(self.pageFwd)
        pgNum = Q.makeLabel("", 15)

        self.layout.addStretch(1)

        self.pagination, _ = Q.makeSeries(
            Q.HORIZONTAL, prevPg, Q.STRETCH, pgNum, Q.STRETCH, nextPg
        )
        self.layout.addWidget(self.pagination)

        self.sync()

    def pageBack(self):
        """
        Go back one page.
        """
        newPg = self.page + 1
        if newPg > len(self.pages) - 1:
            newPg = 0
        self.page = newPg
        self.setAgendaWidgets(self.pages[newPg])
        self.setPgNum()

    def pageFwd(self):
        """
        Go the the next displayed page.
        """
        newPg = self.page - 1
        if newPg < 0:
            newPg = len(self.pages) - 1
        self.page = newPg
        self.setAgendaWidgets(self.pages[newPg])
        self.setPgNum()

    def setPgNum(self):
        """
        Set the displayed page number.
        """
        self.pgNum.setText("%d/%d" % (self.page + 1, len(self.pages)))

    def sync(self):
        """
        Set the dcrdata blockchain on connected signal. Then set agendas.
        """

        def getagendas():
            # dcrdata will send 422 Unprocessible Entity if on simnet.
            try:
                return self.blockchain.getAgendasInfo().agendas
            except Exception:
                log.warning("error fetching agendas. OK on simnet")

        app.makeThread(getagendas, self.setAgendas)

    def setAgendas(self, agendas):
        """
        Set agendas from dcrdata.
        """

        if not agendas:
            return

        self.agendas = agendas
        self.pages = [
            agendas[i * 2 : i * 2 + 2] for i in range((len(agendas) + 1) // 2)
        ]
        self.page = 0
        self.setAgendaWidgets(self.pages[0])
        self.pagination.setVisible(len(self.pages) > 1)

    def setVote(self):
        """
        Set the users current vote choice.
        """

        self.voteSet = False
        if len(self.agendas) == 0:
            app.appWindow.showError("unable to set vote: no agendas")
            return
        acct = self.account
        if not acct:
            log.error("no account selected")
            app.appWindow.showError("unable to update votes: no account")
            return
        pools = acct.stakePools
        if len(pools) == 0:
            app.appWindow.showError("unable to set vote: no pools")
            return
        voteBits = pools[0].purchaseInfo.voteBits
        for dropdown in self.dropdowns:
            originalIdx = dropdown.currentIndex()
            index = 0
            if voteBits != 1:
                bits = voteBits & dropdown.bitMask
                for idx in range(len(dropdown.voteBitsList)):
                    # Check if this flag is set.
                    if bits == dropdown.voteBitsList[idx]:
                        index = idx
                        break
                else:
                    app.appWindow.showError(
                        "unable to set vote: vote " + "bit match not found"
                    )
                    return
            if originalIdx != index:
                dropdown.setCurrentIndex(index)
        self.voteSet = True

    def setAgendaWidgets(self, agendas):
        """
        Set the displayed agenda widgets.
        """
        if len(agendas) == 0:
            app.appWindow.showError("unable to set agendas")
            return
        Q.clearLayout(self.agendasLyt, delete=True)
        self.dropdowns.clear()
        for agenda in agendas:
            nameLbl = Q.makeLabel(agenda.id, 16)
            statusLbl = Q.makeLabel(agenda.status, 14)
            descriptionLbl = Q.makeLabel(agenda.description, 14)
            descriptionLbl.setMargin(10)
            choices = [choice.id for choice in agenda.choices]
            nameWgt, _ = Q.makeRow(nameLbl, Q.STRETCH, statusLbl)

            # choicesDropdown is a dropdown menu that contains voting choices.
            choicesDropdown = Q.makeDropdown(choices)
            self.dropdowns.append(choicesDropdown)
            # Vote bit indexes are the same as the dropdown's choice indexes.
            voteBits = [choice.bits for choice in agenda.choices]
            choicesDropdown.voteBitsList = voteBits
            choicesDropdown.bitMask = agenda.mask
            choicesDropdown.lastIndex = 0
            choicesDropdown.activated.connect(self.onChooseChoiceFunc(choicesDropdown))

            choicesWgt, _ = Q.makeRow(choicesDropdown)
            wgt, lyt = Q.makeColumn(nameWgt, descriptionLbl, choicesWgt)
            wgt.setMinimumWidth(360)
            lyt.setContentsMargins(5, 5, 5, 5)
            Q.addDropShadow(wgt)
            self.agendasLyt.addWidget(wgt, 1)

    def onChooseChoiceFunc(self, dropdown):
        """
        Called when a user has changed their vote. Changes the vote bits for
        the dropdown's bit mask.

        Args:
            dropdown (obj): the drowdown related to this function.

        Returns:
            func: A function that is called upon the dropdown being activated.
        """

        def func(idx):
            if idx == dropdown.lastIndex:
                return
            acct = self.account
            pools = acct.stakePools
            voteBits = pools[0].purchaseInfo.voteBits
            maxuint16 = (1 << 16) - 1
            # Erase all choices.
            voteBits &= maxuint16 ^ dropdown.bitMask
            # Set the current choice.
            voteBits |= dropdown.voteBitsList[dropdown.currentIndex()]

            def changeVote():
                app.emitSignal(ui.WORKING_SIGNAL)
                try:
                    pools[0].setVoteBits(voteBits)
                    app.appWindow.showSuccess("vote choices updated")
                    dropdown.lastIndex = idx
                except Exception as e:
                    log.error("error changing vote: %s" % e)
                    app.appWindow.showError(
                        "unable to update vote choices: pool connection"
                    )
                    dropdown.setCurrentIndex(dropdown.lastIndex)
                app.emitSignal(ui.DONE_SIGNAL)

            app.makeThread(changeVote)

        return func


class PoolAccountScreen(Screen):
    """
    A screen that lists currently known VSP accounts, and allows adding new
    accounts or changing the selected account.
    """

    def __init__(self, acct, poolScreen):
        """
        Args:
            app (TinyWallet): The TinyWallet application instance.
            poolScreen: The screen for adding VSPs.
        """
        super().__init__()
        self.isPoppable = True
        self.canGoHome = True

        self.account = acct
        self.pages = []
        self.page = 0

        self.poolScreen = poolScreen
        app.registerSignal(ui.SYNC_SIGNAL, self.setPools)
        self.wgt.setMinimumWidth(400)
        self.wgt.setMinimumHeight(225)

        lbl = Q.makeLabel("Accounts", 18)
        self.layout.addWidget(lbl, 0, Q.ALIGN_LEFT)

        wgt, self.poolsLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.poolsLyt.setSpacing(10)
        self.poolsLyt.setContentsMargins(5, 5, 5, 5)
        self.layout.addWidget(wgt)

        self.prevPg = app.getButton(TINY, "back")
        self.prevPg.clicked.connect(self.pageBack)
        self.nextPg = app.getButton(TINY, "next")
        self.nextPg.clicked.connect(self.pageFwd)
        self.pgNum = Q.makeLabel("", 15)

        self.layout.addStretch(1)

        self.pagination, _ = Q.makeSeries(
            Q.HORIZONTAL, self.prevPg, Q.STRETCH, self.pgNum, Q.STRETCH, self.nextPg
        )
        self.layout.addWidget(self.pagination)

        btn = app.getButton(SMALL, "add new acccount")
        btn.clicked.connect(self.addClicked)
        self.layout.addWidget(btn)

    def stacked(self):
        """
        stacked is called on screens when stacked by the TinyDialog.
        """
        self.setPools()

    def pageBack(self):
        """
        Go back one page.
        """
        newPg = self.page + 1
        if newPg > len(self.pages) - 1:
            newPg = 0
        self.page = newPg
        self.setWidgets(self.pages[newPg])
        self.setPgNum()

    def pageFwd(self):
        """
        Go the the next displayed page.
        """
        newPg = self.page - 1
        if newPg < 0:
            newPg = len(self.pages) - 1
        self.page = newPg
        self.setWidgets(self.pages[newPg])
        self.setPgNum()

    def setPgNum(self):
        """
        Set the displayed page number.
        """
        self.pgNum.setText("%d/%d" % (self.page + 1, len(self.pages)))

    def setPools(self):
        """
        Reset the stake pools list from that active account and set the first
        page.
        """
        acct = self.account
        if not acct:
            log.error("no account selected")
        pools = acct.stakePools
        if len(pools) == 0:
            return
        # Refresh purchase info
        try:
            pools[0].updatePurchaseInfo()
        except Exception as e:
            log.error("error fetching purchase info: %s" % e)
        # Notify that vote data should be updated.
        app.emitSignal(ui.PURCHASEINFO_SIGNAL)
        self.pages = [pools[i * 2 : i * 2 + 2] for i in range((len(pools) + 1) // 2)]
        self.page = 0
        self.setWidgets(self.pages[0])
        self.pagination.setVisible(len(self.pages) > 1)
        self.setPgNum()

    def setWidgets(self, pools):
        """
        Set the displayed pool widgets.

        Args:
            pools list(VotingServiceProvider): pools to display
        """
        Q.clearLayout(self.poolsLyt, delete=True)
        for pool in pools:
            ticketAddr = pool.purchaseInfo.ticketAddress
            urlLbl = Q.makeLabel(pool.url, 16)
            addrLbl = Q.makeLabel(ticketAddr, 14)
            wgt, lyt = Q.makeColumn(urlLbl, addrLbl, align=Q.ALIGN_LEFT)
            wgt.setMinimumWidth(360)
            lyt.setContentsMargins(5, 5, 5, 5)
            Q.addDropShadow(wgt)
            Q.addClickHandler(wgt, lambda p=pool: self.selectActivePool(p))
            self.poolsLyt.addWidget(wgt, 1)

    def selectActivePool(self, pool):
        """
        Set the current active pool.

        Args:
            pool (VotingServiceProvider): The new active pool.
        """
        app.appWindow.showSuccess("new pool selected")
        self.account.setPool(pool)
        self.setPools()

    def addClicked(self, e=None):
        """
        The clicked slot for the add pool button. Stacks the pool screen.
        """
        app.appWindow.pop(self)
        app.appWindow.stack(self.poolScreen)


class ConfirmScreen(Screen):
    """
    A screen that displays a custom prompt and calls a callback function
    conditionally on user affirmation. The two available buttons say "ok" and
    "no". Clicking "ok" triggers the callback. Clicking "no" simply pops this
    Screen.
    """

    def __init__(self):
        super().__init__()
        self.isPoppable = True
        self.canGoHome = False

        self.callback = None
        self.prompt = Q.makeLabel("", 16)
        self.prompt.setWordWrap(True)
        self.layout.addWidget(self.prompt)
        stop = app.getButton(SMALL, "no")
        stop.clicked.connect(self.stopClicked)
        go = app.getButton(SMALL, "ok")
        go.clicked.connect(self.goClicked)
        wgt, _ = Q.makeRow(Q.STRETCH, stop, Q.STRETCH, go, Q.STRETCH)
        wgt.setContentsMargins(0, 20, 0, 0)
        self.layout.addWidget(wgt)

    def withPurpose(self, prompt, callback):
        """
        Set the prompts and callback and return self.

        Args:
            prompt (string): The prompt for the users.
            callback (function): The function to call when the user clicks "ok".

        Returns:
            ConfirmScreen: This instance. Useful for using a pattern like
                app.appWindow.stack(
                    confirmScreen.withPurpose("go ahead?", callbackFunc))
        """
        self.prompt.setText(prompt)
        self.callback = callback
        return self

    def stopClicked(self, e=None):
        """
        The user has clicked "no". Just pop this screen.
        """
        app.appWindow.pop(self)

    def goClicked(self, e=None):
        """
        The user has clicked the "ok" button. Pop self and call the callback.
        """
        app.appWindow.pop(self)
        if self.callback:
            self.callback()


class Spinner(QtWidgets.QLabel):
    """
    A waiting/loading spinner.
    """

    def __init__(self, spinnerSize, penWidth=4, pad=2):
        """
        Args:
            spinnerSize (int): Pixel width and height of the spinner.
            penWidth (int): The width of the line.
            pad (int): Additional padding to place around the spinner.
        """
        super().__init__()
        self.period = 1  # 1 rotation per second
        self.penWidth = penWidth
        self.setFixedSize(spinnerSize, spinnerSize)
        self.c = spinnerSize / 2.0

        p = penWidth + pad
        self.rect = (p, p, spinnerSize - 2 * p, spinnerSize - 2 * p)

        ani = self.ani = QtCore.QVariantAnimation()
        ani.setDuration(86400 * 1000)  # give it a day
        ani.setStartValue(0.0)
        ani.setEndValue(1000.0)
        ani.valueChanged.connect(self.update)
        self.showEvent = lambda e: self.ani.start()
        self.hideEvent = lambda e: self.ani.stop()

    def getPen(self):
        g = QtGui.QConicalGradient(self.c, self.c, 0)
        g.setColorAt(0.0, QtGui.QColor("black"))
        g.setColorAt(1.0, QtGui.QColor("white"))
        g.setAngle((time.time() % self.period) / self.period * -360)
        return QtGui.QPen(QtGui.QBrush(g), self.penWidth, cap=QtCore.Qt.RoundCap)

    def paintEvent(self, e):
        super().paintEvent(e)
        painter = QtGui.QPainter(self)
        painter.setRenderHints(QtGui.QPainter.HighQualityAntialiasing)
        painter.setPen(self.getPen())
        painter.drawEllipse(*self.rect)


class SVGWidget(Clicker, QtSvg.QSvgWidget):
    """
    A widget to display an SVG.
    """

    def __init__(self, path, w=None, h=None, click=None):
        """
        Create a QSvgWidget from the svg file in the icons directory. The svg will
        display at its designated pixel size if no dimensions are specified. If
        only one dimension is specified, the aspect ratio will be maintained for the
        other dimension.

        Args:
            path (str): Full path for non-tinywallet files. Otherwise, the basename
                of the file in the icons folder.
            w (int): optional. Pixel width of the resulting pixmap.
            h (int): optional. Pixel height of the resulting pixmap.
            click (func): optional. A function to call when the widget is
                clicked.

        Returns:
            QPixmap: A sized pixmap created from the scaled SVG file.
        """
        if not path.endswith(".svg"):
            path = os.path.join(UI_DIR, "icons", path + ".svg")
        QtSvg.QSvgWidget.__init__(self, path)
        Clicker.__init__(self, click)
        size = self.sizeHint()
        x, y = size.width(), size.height()
        if w and h:
            pass
        elif w:
            h = w * y / x
        elif h:
            w = h * x / y
        else:
            w, h = x, y
        self.w = w
        self.h = h
        self.setFixedSize(w, h)

    def icon(self):
        return QtGui.QIcon(self.grab())


class HorizontalRule(QtWidgets.QFrame):
    """
    A plain horizontal line.
    """

    def __init__(self, color="#b2b2b2"):
        """
        Args:
            color (str): A QCSS color string.
        """
        super().__init__()
        self.setFrameShape(QtWidgets.QFrame.HLine)
        self.setFixedHeight(1)
        self.setStyleSheet(f"QFrame{{border: 2px solid {color};}}")


class AddressDisplay(QtWidgets.QLabel):
    """
    A box to display an address.
    """

    def __init__(self, *a):
        super().__init__(*a)
        font = self.font()
        font.setPixelSize(14)
        self.setFont(font)
        self.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)


def withUnlockedAccount(acct, f, cb):
    """
    Run the provided function with the account open. If the account is not
    already open, the user will be prompted for their password and the account
    opened before the function is run.

    Args:
        f (func): A function to run with the account open.
        cb (func(x)): A callback to receive the return value from f.
    """
    if acct.isUnlocked():
        app.waitThread(f, cb)
        return

    def done(ret):
        app.appWindow.pop(app.waitingScreen)
        app.appWindow.pop(app.pwDialog)
        cb(ret)

    def withpw(pw):
        try:
            app.waiting()
            cryptoKey = app.wallet.cryptoKey(pw)
            acct.unlock(cryptoKey)
            app.waitThread(f, done)
        except Exception as e:
            log.warning(
                "exception encountered while performing wallet action: %s"
                % formatTraceback(e)
            )
            app.appWindow.showError("error")

    app.getPassword(withpw)


def unlockAccount(acct, cb):
    """
    Similar to withUnlockedAccount, but doesn't run a function, just a callback
    once the accopunt is successfully unlocked.

    Args:
        cb (func(x)): A callback to receive the return value from f.
    """
    withUnlockedAccount(acct, lambda: True, cb)
