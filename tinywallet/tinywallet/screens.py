"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, the Decred developers
See LICENSE for detail
"""

import os
import random
import shutil
import threading
import time
from urllib.parse import urlsplit, urlunsplit
import webbrowser

from PyQt5 import QtCore, QtGui, QtSvg, QtWidgets

from decred import DecredError
from decred.crypto import crypto
from decred.dcr import constants as DCR, nets
from decred.dcr.blockchain import LocalNode
from decred.dcr.txscript import DefaultRelayFeePerKb
from decred.dcr.vsp import VotingServiceProvider
from decred.util import chains, database, helpers
from decred.util.helpers import formatTraceback
from decred.wallet.wallet import Wallet

from . import config, qutilities as Q, ui
from .config import DB
from .ui import SMALL, TINY


UI_DIR = os.path.dirname(os.path.realpath(__file__))
log = helpers.getLogger("APPUI")
cfg = config.load()

# A key to identify the screen fade in animation.
FADE_IN_ANIMATION = "fadeinanimation"

app = None


def openInBrowser(url):
    """
    Open a URL in the user's browser.

    Args:
        url (string): the URL to open.
    """
    webbrowser.open(url, new=2)


def sprintDcr(atoms, comma=""):
    """
    Helper to format dcr amounts.

    Args:
        atoms (int): Amount of dcr in atoms to convert to coins.
        comma (str): Separator to add to the end of the string.

    Returns:
        str: Formatted dcr amount.
    """
    return f"{atoms / 1e8:.2f} dcr{comma}"


def sprintAmount(thing):
    """
    Helper to produce functions that format amounts of thing.

    Args:
        thing (str): The thing to stringify amounts for.

    Returns:
        func(int, str)str: Function to stringify amounts of thing.
    """
    return lambda n, comma="": f"{n} {thing}{'' if n == 1 else 's'}{comma}"


def blksLeftStakeWindow(height, netParams):
    """
    Return the number of blocks until the next stake difficulty change.

    Args:
        height (int): Block height to find remaining blocks from.
        netParams (module): The network parameters.

    Returns:
        int: The number of blocks left in the current window.
    """
    window = netParams.StakeDiffWindowSize
    # Add one to height, to account for the genesis block.
    return window - (height + 1) % window


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

        # A little spinner shown while the wallet is locked.
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

        # Some styling for the callout.
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
        # log.debug(f"stack setting top screen to {type(w).__name__}")
        w.runAnimation(FADE_IN_ANIMATION)
        w.setVisible(True)
        self.setIcons(w)
        self.setVisible(True)
        w.stacked()

    def pop_(self, screen=None):
        """
        Pop the top screen from the stack. If a Screen instance is provided,
        only pop if that is the top screen.

        Args:
            screen (Screen): optional. The particular screen to pop.
        """
        widgetList = list(Q.layoutWidgets(self.layout))
        if len(widgetList) < 2:
            return
        popped, top = widgetList[-1], widgetList[-2]
        if screen and popped is not screen:
            return
        popped.setVisible(False)
        self.layout.removeWidget(popped)
        popped.unstacked()
        top.setVisible(True)
        top.runAnimation(FADE_IN_ANIMATION)
        self.setIcons(top)

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
            wgt.unstacked()
            self.layout.removeWidget(wgt)
        home.setVisible(True)
        home.runAnimation(FADE_IN_ANIMATION)
        self.layout.addWidget(home)
        home.stacked()
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
        the window and its application panel icon are hidden, but the
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
        Show a success message with a light green background.

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
        Paint the callout in the appropriate place.
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
    should inherit from Screen.
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

        # The layout that the child will use is actually a 2nd descendent of
        # the primary Screen layout. Stretches are used to center a widget
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
        if not v:
            self.animations.pop(FADE_IN_ANIMATION, None)
            return
        effect = QtWidgets.QGraphicsOpacityEffect(self)
        self.animations[FADE_IN_ANIMATION] = a = QtCore.QPropertyAnimation(
            effect, b"opacity"
        )
        a.setDuration(550)
        a.setStartValue(0)
        a.setEndValue(1)
        a.setEasingCurve(QtCore.QEasingCurve.OutQuad)
        self.setGraphicsEffect(effect)

    def stacked(self):
        """
        Can be implemented by inheriting classes. Will be called when the
        screen is stacked.
        """
        pass

    def unstacked(self):
        """
        Can be implemented by inheriting classes. Will be called when the
        screen is unstacked.
        """
        pass


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
        self.settingsScreen = AccountSettingsScreen(
            self.account.relayFee, self.saveName, self.setRelayFee
        )
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
        self.address = Q.makeLabel("", 14)
        self.address.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        box, lyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        lyt.addWidget(self.address, 0, Q.ALIGN_TOP)
        Q.addDropShadow(box)
        lyt.setContentsMargins(5, 2, 5, 0)
        box.setContentsMargins(5, 5, 5, 5)

        left, _ = Q.makeColumn(Q.STRETCH, row, box)
        left.setContentsMargins(5, 5, 5, 10)

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

        log.debug(f"sending {val} to {address}")

        def send():
            try:
                return self.account.sendToAddress(
                    int(round(val * 1e8)), address
                )  # raw transaction
            except Exception as e:
                log.error(f"failed to send: {formatTraceback(e)}")
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
            newName (str): The new account name.
        """
        self.account.name = newName
        self.acctMgr.saveAccount(self.account.idx)
        self.nameLbl.setText(self.account.name)
        self.assetScreen.doButtons()
        app.home()

    def setRelayFee(self, relayFee):
        """
        Changes and saves the relayFee of the account.

        Args:
            int: The new relayFee.
        """
        self.acctMgr.setRelayFee(self.account.idx, relayFee)

    def stackAndSync(self):
        """
        Start syncing the account.
        """
        if self.account.synced:
            app.home(self)
            return

        def done(ret):
            if ret:
                app.emitSignal(ui.SYNC_SIGNAL)

        def sync():
            if not self.account.isUnlocked():
                return
            try:
                app.emitSignal(ui.WORKING_SIGNAL)
                app.home(self)
                return self.account.sync()
            finally:
                app.emitSignal(ui.DONE_SIGNAL)

        withUnlockedAccount(self.account, sync, done)


class PasswordDialog(Screen):
    """
    PasswordDialog is a simple form for getting a user-supplied password.
    """

    def __init__(self):
        super().__init__()
        content, mainLayout = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.layout.addWidget(Q.pad(content, 20, 20, 20, 20))
        mainLayout.setSpacing(10)
        self.isPoppable = True
        self.canGoHome = False
        self.promptText = "Password"

        # Password is not stacked directly, but by using withCallback. The
        # callback is set there.
        self.callback = lambda pw: True

        # The default prompt text is "Password", but different text can be
        # specified in withCallback.
        self.prompt = QtWidgets.QLabel(self.promptText)
        mainLayout.addWidget(self.prompt)
        pw = self.pwInput = QtWidgets.QLineEdit()

        # The default echo mode of the password input will not show plain text.
        pw.setEchoMode(QtWidgets.QLineEdit.Password)
        pw.setMinimumWidth(250)
        pw.returnPressed.connect(self.done)
        pw.setStyleSheet("QLineEdit{font-size:10px;padding:5px 6px;}")

        # The echo mode can be toggled with the eye icons, only one of which
        # is visible at a time.
        self.showPw = SVGWidget("open-eye", h=20, click=self.showPwClicked)
        self.hidePw = SVGWidget("closed-eye", h=20, click=self.hidePwClicked)
        self.hidePw.setVisible(False)

        # The password will be submitted when enter is pressed, but a button is
        # also offered.
        submit = app.getButton(SMALL, "Go")
        submit.clicked.connect(self.done)
        submit.setFixedWidth(35)

        pwRow, _ = Q.makeRow(pw, self.showPw, self.hidePw, submit)
        mainLayout.addWidget(pwRow)

    def stacked(self):
        """
        Set the cursor when the screen is stacked.
        """
        self.prompt.setText(self.promptText)
        self.pwInput.setFocus()

    def unstacked(self):
        """
        Clear the password field when the screen is popped.
        """
        self.pwInput.setText("")

    def showPwClicked(self, e=None):
        """
        showPwClicked is connected to the open-eye icon clicked signal. Show
        the password in plain text.
        """
        self.showPw.setVisible(False)
        self.hidePw.setVisible(True)
        self.pwInput.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.pwInput.setStyleSheet("QLineEdit{font-size:14px;}")

    def hidePwClicked(self, e=None):
        """
        showPwClicked is connected to the closed-eye icon clicked signal. Set
        the echo mode to password.
        """
        self.showPw.setVisible(True)
        self.hidePw.setVisible(False)
        self.pwInput.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pwInput.setStyleSheet("QLineEdit{font-size:10px;padding:5px 6px;}")

    def done(self, e=None):
        """
        Connected to the submit button's clicked signal. Call the callback
        function with the current password field text.
        """
        self.callback(self.pwInput.text())

    def withCallback(self, callback, prompt="Password"):
        """
        Sets the screens callback function to receive the password field value
        on form submission.

        Args:
            callback (func(str)): A function to receive the user's password.
            prompt (str): optional. The text to display above the password
                field.

        Returns:
            self: The PasswordDialog itself as a convenience.
        """
        self.promptText = prompt
        self.callback = callback
        return self


class Clicker:
    """
    Clicker adds click functionality to any QWidget. Designed for multiple
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
        When the mouse is moved, check whether the mouse is within the bounds
        of the label. If not, set mouseDown to False. The user must click and
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
            *a (tuple): Any additional arguments are passed directly to the
                parent QLabel constructor.
        """
        QtWidgets.QLabel.__init__(self, *a)
        Clicker.__init__(self, callback)


class InitializationScreen(Screen):
    """
    A screen shown when no wallet file is detected. This screen offers options
    for creating a new wallet or loading an existing wallet.
    """

    def __init__(self):
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
        app.getPassword(self.initPasswordCallback, "Create a wallet password")

    def initPasswordCallback(self, pw):
        """
        Create a wallet encrypted with the user-supplied password. The wallet
        will be open to the default account, but will not be locked for use.

        Args:
            pw (str): A user supplied password string.
        """
        # Either way, pop the password window.
        def create():
            try:
                app.dcrdata.connect()
                words, wallet = Wallet.create(app.walletFilename(), pw, cfg.netParams)
                return words, wallet
            except Exception as e:
                log.error(f"failed to create wallet: {formatTraceback(e)}")

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
                msg = "more than one file selected for importing"
                log.error(msg)
                raise Exception(msg)
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
        shutil.move(walletPath, destination)
        app.initialize()

    def restoreClicked(self):
        """
        User has selected to generate a wallet from a mnemonic seed.
        """
        restoreScreen = MnemonicRestorer()
        app.appWindow.stack(restoreScreen)


class AssetControl:
    """
    AssetControl is used for inter-screen communications.
    """

    def __init__(self, acctMgr, settings, node, setNode, connectNode, refreshAccounts):
        """
        Args:
            acctMgr (AccountManager): The asset's account manager.
            settings (database.Bucket): The settings bucket.
            node func() -> LocalNode: A getter for the currently connected node.
            setNode func(LocalNode): A setter for the currently connected node.
            connectNode func() -> LocalNode: This function should connect a
                LocalNode to the currently saved configuration settings.
            refreshAccount func(): Called by screens when a change to the number
                or status of accounts has been made.
        """
        self.acctMgr = acctMgr
        self.settings = settings
        self.node = node
        self.setNode = setNode
        self.connectNode = connectNode
        self.refreshAccounts = refreshAccounts


class AssetScreen(Screen):
    """
    AssetScreen is a screen for choosing one account out of many, or changing
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
        self.configured = False
        self.accountScreens = {}
        assetDir = app.assetDirectory("dcr")
        self.acctMgr = app.wallet.accountManager("dcr", app.blockchainSignals)
        self.settingsDB = database.KeyValueDatabase(assetDir / "settings.db")
        self.settings = self.settingsDB.child("settings")
        self.dcrd = None

        def currentNode():
            return self.dcrd

        ctl = AssetControl(
            acctMgr=self.acctMgr,
            settings=self.settings,
            node=currentNode,
            setNode=self.setNode,
            connectNode=self.connectNode,
            refreshAccounts=self.doButtons,
        )

        self.settingsScreen = AssetSettingsScreen(ctl)

        logo = SVGWidget(DCR.LOGO, h=25)
        lbl = Q.makeLabel("Decred", 25, fontFamily="Roboto Medium")
        gear = SVGWidget("gear", h=20, click=self.gearClicked)
        # Gear icon will lead to an asset settings screen.
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, logo, lbl, Q.STRETCH, gear,)
        self.layout.addWidget(wgt)

        header = Q.makeLabel("Select an account", 20)
        header.setContentsMargins(0, 5, 0, 5)
        header.setAlignment(Q.ALIGN_LEFT)

        # Indicators for the connection status of dcrdata and dcrd.
        self.dcrdLight = Q.makeLabel("\u26ab", 20, color="orange")
        lbl = Q.makeLabel("dcrd", 14)
        dcrdBox, lyt = Q.makeRow(self.dcrdLight, lbl)
        lyt.setSpacing(2)
        Q.addClickHandler(dcrdBox, self.stackDcrd)
        dcrdBox.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.dcrdataLight = Q.makeLabel("\u26ab", 20, color="#76d385")
        lbl = Q.makeLabel("dcrdata", 14)
        dcrdataBox, lyt = Q.makeRow(self.dcrdataLight, lbl)
        lyt.setSpacing(2)
        dcrdataBox.setContentsMargins(0, 0, 20, 0)
        row, _ = Q.makeRow(dcrdataBox, dcrdBox)
        row.setContentsMargins(0, 8, 0, 0)
        row, _ = Q.makeRow(header, Q.STRETCH, row)
        self.layout.addWidget(row)

        wgt, self.accountsList = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        self.layout.addWidget(wgt)

        self.newAcctScreen = NewAccountScreen(ctl)
        self.doButtons()

    def stacked(self):
        """
        Called by the application when this screen is stacked.
        """
        if self.configured:
            return

        # Connect dcrdata.
        self.configured = True
        try:
            app.dcrdata.connect()
        except DecredError as e:
            app.appWindow.showError(f"failed to connect to dcrdata: {e}")
            return

        # Check for a dcrd configuration. If found, request the cryptoKey so the
        # rpcpass can be decrypted and a connection attempted.
        settings = self.settings
        nodeConfigured = DB.rpchost in settings
        if not nodeConfigured:
            return
        if settings[DB.dcrdon] != database.TRUE:
            return

        def withNode(node):
            if not node or not node.connected():
                app.appWindow.showError("could not connect to dcrd")
                return
            self.setNode(node)

        self.connectNode(withNode)

    def shutdown(self):
        """
        Called by the application at shutdown. Handle all Decred-related
        shutdown actions.
        """
        blockchain = chains.chain("dcr")
        if blockchain:
            blockchain.close()
        if self.dcrd:
            self.dcrd.close()
        self.settingsScreen.shutdown()

    def setNode(self, node):
        """
        Set the currently saved LocalNode and inform the AccountManager. Set the
        indicator light.

        Args:
            node (LocalNode): The new dcrd connection.
        """
        Q.setProperties(self.dcrdLight, color="#76d385" if node else "orange")
        self.dcrd = node
        self.settings[DB.dcrdon] = database.TRUE if node else database.FALSE
        self.acctMgr.setNode(node)

    def connectNode(self, done):
        """
        Attempt to get a node with the currently stored configuration.

        Args:
            done func(LocalNode): A receiver for the node. If a node cannot be
                found, None is passed.
        """
        settings = self.settings
        if DB.rpcuser not in settings:
            done(None)

        def withCK4dcrd(cryptoKey):
            rpcPass = crypto.decrypt(cryptoKey, settings[DB.rpcpass]).b.decode()
            return LocalNode(
                netParams=cfg.netParams,
                dbPath=app.assetDirectory("dcr") / "localnode.db",
                url=settings[DB.rpchost].decode(),
                user=settings[DB.rpcuser].decode(),
                pw=rpcPass,
                certPath=settings[DB.rpccert].decode(),
            )

        app.withCryptoKey(withCK4dcrd, done, prompt="Enter password to connect to dcrd")

    def stackDcrd(self, e=None):
        """
        Connected to the dcrd indicator light.
        """
        app.appWindow.stack(self.settingsScreen.dcrdConfigScreen)

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
    """
    A screen to adjust asset-specific settings.
    """

    def __init__(self, ctl):
        """
        Args:
            ctl (AssetControl): The shared asset data.
        """
        super().__init__()
        self.canGoHome = True
        self.isPoppable = True

        self.ctl = ctl
        self.blockchain = chains.chain("dcr")

        self.dcrdConfigScreen = DCRDConfigScreen(ctl)

        self.wgt.setFixedSize(
            TinyDialog.maxWidth * 0.9,
            TinyDialog.maxHeight * 0.9 - TinyDialog.topMenuHeight,
        )

        gear = SVGWidget("gear", h=20)
        lbl = Q.makeLabel("Decred Settings", 22)
        wgt, _ = Q.makeRow(gear, lbl, Q.STRETCH)
        self.layout.addWidget(wgt)

        self.layout.addStretch(1)

        # Add a QLineEdit to change the dcrdata endpoint.
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
        row += 1

        # Add a button that allows connecting to a local dcrd RPC server.
        lbl = Q.makeLabel(
            "The wallet is faster and more secure when"
            " connected directly to a dcrd RPC server.",
            14,
            Q.ALIGN_LEFT,
        )
        lbl.setWordWrap(True)
        lbl.setContentsMargins(0, 20, 0, 0)
        grid.addWidget(lbl, row, 0, 1, 2)
        row += 1
        bttn = app.getButton(SMALL, "configure dcrd")
        bttn.clicked.connect(self.connectDcrdClicked)
        bttnRow, _ = Q.makeRow(bttn, Q.STRETCH)
        grid.addWidget(bttnRow, row, 0, 1, 2)
        row += 1

        self.layout.addStretch(1)

    def shutdown(self):
        """
        Called when the application is shut down.
        """
        self.dcrdConfigScreen.shutdown()

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

    def connectDcrdClicked(self, e=None):
        """
        Qt slot connected to "connect to dcrd" button. Stacks a dcrd
        configuration screen.
        """
        app.appWindow.stack(self.dcrdConfigScreen)


class DCRDConfigScreen(Screen):
    """
    A screen to adjust dcrd-specific settings.
    """

    foundMsg = (
        "A dcrd RPC server was found with these settings."
        " Would you like to use this server?"
    )
    notFoundMsg = "Enter your dcrd connection details."

    def __init__(self, ctl):
        """
        Args:
            ctl (AssetControl): The shared asset data.
        """
        super().__init__()
        self.canGoHome = True
        self.isPoppable = True
        self.wgt.setFixedSize(
            TinyDialog.maxWidth * 0.8,
            TinyDialog.maxHeight * 0.9 - TinyDialog.topMenuHeight,
        )
        self.ctl = ctl

        # If a node is found by a search of the default config file location,
        # it will be stored temporarily in tmpNode. Once the user confirms their
        # intention to use the server, AssetControl.setNode be called.
        self.tmpNode = None
        self.tmpConfig = None

        self.layout.addStretch(1)

        # Try to auto-fill the fields with data from a config file at the
        # default location. This info will persist, even if a connection cannot
        # be made with these credentials in stacked.
        node = ctl.node()
        if node:
            nodeConfig = dict(rpchost=ctl.settings[DB.rpchost],)
        else:
            nodeConfig = config.dcrd(cfg.netParams)

        self.remoteForm, grid = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        self.remoteForm.setVisible(node is None)
        self.layout.addWidget(self.remoteForm)
        row = 0

        def insertSpace():
            spacer = Q.makeLabel("", 5)
            spacer.setContentsMargins(0, 5, 0, 0)
            grid.addWidget(spacer, row, 0, 1, 4)

        # The header text depends on whether we are displaying information found
        # automatically, or only expecting user input.
        self.header = lbl = Q.makeLabel(self.notFoundMsg, 14)
        lbl.setWordWrap(True)
        lbl.setAlignment(Q.ALIGN_LEFT)
        lbl.setFixedHeight(40)
        grid.addWidget(lbl, row, 0, 1, 4)
        row += 1

        # URL and user name.
        grid.addWidget(Q.makeLabel("dcrd URL", 14, Q.ALIGN_LEFT), row, 0, 1, 3)
        grid.addWidget(Q.makeLabel("RPC username", 14, Q.ALIGN_LEFT), row, 3)
        row += 1
        defaultRpclisten = f"127.0.0.1:{nets.DcrdPorts[cfg.netParams.Name]}"
        host = nodeConfig.get("rpclisten", defaultRpclisten)

        self.rpcListen = QtWidgets.QLineEdit(f"https://{host}/")
        grid.addWidget(self.rpcListen, row, 0, 1, 3)
        self.rpcUser = QtWidgets.QLineEdit(nodeConfig.get("rpcuser", ""))
        grid.addWidget(self.rpcUser, row, 3)
        row += 1
        insertSpace()
        row += 1

        # TLS certificate info. This row has a little button that opens a file
        # dialog.
        grid.addWidget(Q.makeLabel("TLS certificate", 14, Q.ALIGN_LEFT), row, 0, 1, 3)
        row += 1
        self.certPath = QtWidgets.QLineEdit(nodeConfig.get("rpccert", ""))
        grid.addWidget(self.certPath, row, 0, 1, 3)
        pickaFile = app.getButton(TINY, "choose a file")
        pickaFile.clicked.connect(self.pickaFileClicked)
        pickaFile.setIcon(SVGWidget("folder", h=12).icon())
        pickRow, _ = Q.makeRow(pickaFile, Q.STRETCH)
        grid.addWidget(pickRow, row, 3)
        row += 1
        insertSpace()
        row += 1

        # Password and submit button. Password has a litte eye icon to click
        # to toggle the password to plain text. Default is password mode.
        grid.addWidget(Q.makeLabel("RPC password", 14, Q.ALIGN_LEFT), row, 0, 1, 2)
        row += 1
        bttn = self.rpcPass = QtWidgets.QLineEdit(nodeConfig.get("rpcpass", ""))
        bttn.setContentsMargins(0, 0, 0, 10)
        bttn.setEchoMode(QtWidgets.QLineEdit.Password)
        bttn.setStyleSheet("QLineEdit{font-size:10px;}")
        self.showPw = SVGWidget("open-eye", h=20, click=self.showPwClicked)
        self.hidePw = SVGWidget("closed-eye", h=20, click=self.hidePwClicked)
        self.hidePw.setVisible(False)
        vizBttns, _ = Q.makeRow(self.showPw, self.hidePw)
        vizBttns.setContentsMargins(0, 4, 0, 4)
        pwRow, _ = Q.makeRow(bttn, vizBttns)
        grid.addWidget(pwRow, row, 0, 1, 3)
        self.submitBttn = app.getButton(SMALL, "connect")
        self.submitBttn.clicked.connect(self.submitBttnClicked)
        self.useTmpBttn = app.getButton(SMALL, "use these settings")
        self.useTmpBttn.clicked.connect(self.useTempNodeClicked)
        self.useTmpBttn.setVisible(False)
        bttns, _ = Q.makeRow(self.submitBttn, self.useTmpBttn)
        grid.addWidget(bttns, row, 3)
        row += 1
        [grid.setColumnStretch(i, 1) for i in range(4)]
        for edit in (self.rpcListen, self.rpcUser, self.certPath, self.rpcPass):
            edit.textEdited.connect(self.fieldEdited)

        # When tinywallet is already connected to a node, the only thing shown
        # is a message and an option to disconnect.
        self.connectedWgt, lyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.layout.addWidget(self.connectedWgt)
        self.connectedLbl = Q.makeLabel("", 15)
        lyt.addWidget(self.connectedLbl)
        self.hostLbl = Q.makeLabel("", 17, fontFamily="Roboto Medium")
        self.hostLbl.setContentsMargins(0, 5, 0, 5)
        lyt.addWidget(self.hostLbl)
        self.onToggle = Q.Toggle(callback=self.connectionToggled)
        row, _ = Q.makeRow(
            Q.STRETCH,
            Q.makeLabel("off", 14),
            self.onToggle,
            Q.makeLabel("on", 14),
            Q.STRETCH,
        )
        lyt.addWidget(row)
        clear = ClickyLabel(self.clearNode, "forget this node")
        Q.setProperties(clear, underline=True, fontSize=14, color="blue")
        clear.setAlignment(Q.ALIGN_CENTER)
        clear.setContentsMargins(0, 10, 0, 0)
        lyt.addWidget(clear)

        self.layout.addStretch(1)

    def shutdown(self):
        """
        Shut down any stored temporary LocalNode.
        """
        self.dumpTempNode()

    def stacked(self):
        """
        Called when the screen is stacked. Look at current node configuration
        and decide what to show.
        """
        # If dcrd is configured, do nothing.
        if self.readConfig():
            return

        # There is no connection configured. Check for a config file and if one
        # is found, try to connect.
        nodeConfig = config.dcrd(cfg.netParams)
        if not nodeConfig:
            # There is no config file in the default location. The user will
            # have to manually enter details, or point towards a non-default
            # config file location.
            self.showLive(False)
            return

        def receiveNode(node):
            if not node:
                return
            if node.connected():
                self.tmpNode = node
                self.tmpConfig = nodeConfig
                self.rpcListen.setText(nodeConfig["rpclisten"])
                self.rpcUser.setText(nodeConfig["rpcuser"])
                self.certPath.setText(nodeConfig["rpccert"])
                self.rpcPass.setText(nodeConfig["rpcpass"])
                self.showLive(True)
            else:
                self.showLive(False)

        def tryConnect():
            try:
                return LocalNode(
                    netParams=cfg.netParams,
                    dbPath=app.assetDirectory("dcr") / "localnode.db",
                    url=nodeConfig["rpclisten"],
                    user=nodeConfig["rpcuser"],
                    pw=nodeConfig["rpcpass"],
                    certPath=nodeConfig["rpccert"],
                )

            except Exception as e:
                log.debug(
                    "Auto-location attempt failed to connect"
                    f" (not an error): {formatTraceback(e)}"
                )

        app.waitThread(tryConnect, receiveNode)

    def unstacked(self):
        """
        Called when the screen is unstacked. Shut down any stored temporary
        node.
        """
        self.dumpTempNode()
        self.rpcPass.setText("")

    def showLive(self, show):
        """
        Whether the header and buttons should indicate that a server was
        discovered automatically or not.

        Args:
            show (bool): If True, show a message indicating an RPC server was
                discovered, and the user can choose to accept the discovered
                credentials. If False, the message inidicates that manual entry
                of credentials is required.
        """
        self.header.setText(self.foundMsg if show else self.notFoundMsg)
        self.submitBttn.setVisible(not show)
        self.useTmpBttn.setVisible(show)

    def readConfig(self):
        """
        Shows the configuration form if dcrd is not configured, else the
        on/off switch.

        Returns:
            bool: True if dcrd is currently configured.
        """
        ctl = self.ctl
        node = ctl.node()
        nodeConfigured = DB.rpchost in self.ctl.settings
        self.onToggle.set(node and node.connected())
        if nodeConfigured:
            self.remoteForm.setVisible(False)
            self.connectedWgt.setVisible(True)
            self.hostLbl.setText(ctl.settings[DB.rpchost].decode())
            if node and node.connected():
                self.connectedLbl.setText("Connected to dcrd")
            else:
                self.connectedLbl.setText("Connection to dcrd is currently off")
        else:
            self.remoteForm.setVisible(True)
            self.connectedWgt.setVisible(False)

        return nodeConfigured

    def connectionToggled(self, on):
        """
        Connected to the connection on/off toggle switch.
        """
        node = self.ctl.node()
        if on:
            if node:
                node.connect()
                self.ctl.setNode(node)
            else:

                def withDCRD(node):
                    if node:
                        self.ctl.setNode(node)

                self.ctl.connectNode(withDCRD)

        else:
            node.close()
            self.ctl.setNode(None)

    def fieldEdited(self, s):
        """
        Field editing is equivalent to rejecting the auto-discovered node, so
        dump it and show the right header and buttons.
        """
        self.showLive(False)
        self.dumpTempNode()

    def dumpTempNode(self):
        """
        If there is a temporary (discovered) node, close it and clear the
        reference.
        """
        if self.tmpNode:
            self.tmpNode.close()
            self.tmpNode = None
            self.tmpConfig = None

    def pickaFileClicked(self, e=None):
        """
        Connected to the TLS certificate file selection button's clicked signal.
        Show a file dialog for the user to select a TLS certificate. The
        certPath QLineEdit will be set with the selected file's path.
        """
        filename = QtWidgets.QFileDialog.getOpenFileName(
            parent=self, caption="Select a file", filter="TLS Certificates (*.cert)",
        )[0]
        if filename:
            self.certPath.setText(filename)

    def submitBttnClicked(self, e=None):
        """
        Connected to the submission button's clicked signal. Try to connect
        with the current credentials. If successful, store the credentials and
        call AssetControl.setNode.
        """

        rpcURL = self.rpcListen.text()
        if not rpcURL:
            app.appWindow.showError("URL cannot be empty")
        rpcUser = self.rpcUser.text()
        rpcPass = self.rpcPass.text()
        certPath = self.certPath.text()

        def receiveDCRD(node):
            if node.connected():
                app.appWindow.showSuccess("connected to dcrd")
                self.useNode(node, rpcURL, rpcUser, rpcPass, certPath)
            else:
                app.appWindow.showError("failed to connect")

        def runConnectRPC():
            return LocalNode(
                netParams=cfg.netParams,
                dbPath=app.assetDirectory("dcr") / "localnode.db",
                url=rpcURL,
                user=rpcUser,
                pw=rpcPass,
                certPath=certPath,
            )

        app.waitThread(runConnectRPC, receiveDCRD)

    def saveSettings(self, cryptoKey, rpcURL, rpcUser, rpcPass, certPath):
        """
        Save the RPC credentials to the asset settings database bucket.

        Args:
            cryptoKey (SecretKey): The encryption key.
            rpcURL (str): The dcrd 'rpclisten' value, with protocol.
            rpcUser (str): The dcrd 'rpcuser' value.
            rpcPass (str): The dcrd 'rpcpass' value.
            certPath (str): The dcrd 'rpccert' value.
        """
        settings = self.ctl.settings
        settings[DB.rpcuser] = rpcUser.encode()
        settings[DB.rpcpass] = crypto.encrypt(cryptoKey, rpcPass.encode()).b
        settings[DB.rpccert] = certPath.encode()
        settings[DB.rpchost] = rpcURL.encode()

    def useTempNodeClicked(self, e=None):
        """
        Connected to the "use these settings" button's clicked signal. The
        button is shown when a node is found in auto-discovery.
        """
        d = self.tmpConfig
        self.useNode(
            self.tmpNode, d["rpclisten"], d["rpcuser"], d["rpcpass"], d["rpccert"]
        )

    def useNode(self, node, rpcURL, rpcUser, rpcPass, certPath):
        """
        Set the node and save the configuration.

        Args:
            node (LocalNode): The dcrd connection.

        The rest of the arguments are passed directly to saveSettings.
        """

        def withCK(cryptoKey):
            if not cryptoKey:
                return
            self.saveSettings(cryptoKey, rpcURL, rpcUser, rpcPass, certPath)
            return True

        def doneSaving(ret):
            if not ret:
                return
            self.onToggle.set(True)
            self.ctl.setNode(node)
            app.appWindow.showSuccess("connected to dcrd")
            self.tmpNode = self.tmpConfig = None
            app.home()

        app.withCryptoKey(withCK, doneSaving)

    def clearNode(self, e=None):
        """
        Callback for the "forget this node" ClickyLabel. Disconnects and deletes
        the saved configuration for dcrd, after ConfirmScreen.
        """

        def confirmed():
            node = self.ctl.node()
            if node:
                node.close()
            s = self.ctl.settings
            del s[DB.rpchost]
            del s[DB.rpcuser]
            del s[DB.rpccert]
            del s[DB.rpcpass]
            self.ctl.setNode(None)
            app.appWindow.showSuccess("settings cleared")
            app.appWindow.pop(self)

        app.confirm(
            "Are you sure you want to forget the configuration settings for "
            "this connection? ",
            confirmed,
        )

    def showPwClicked(self, e=None):
        """
        Connected to the eye icon. Sets echo mode to normal.
        """
        self.showPw.setVisible(False)
        self.hidePw.setVisible(True)
        self.rpcPass.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.rpcPass.setStyleSheet("QLineEdit{font-size:14px;}")

    def hidePwClicked(self, e=None):
        """
        Connected to the crossed eye icon. Sets echo mode to password.
        """
        self.showPw.setVisible(True)
        self.hidePw.setVisible(False)
        self.rpcPass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.rpcPass.setStyleSheet("QLineEdit{font-size:10px;padding:5px 6px;}")


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

    def __init__(self, relayFee, saveName, setRelayFee):
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
        self.setRelayFee = setRelayFee

        gear = SVGWidget("gear", h=20)
        lbl = Q.makeLabel("Account Settings", 22)
        wgt, _ = Q.makeRow(gear, lbl, Q.STRETCH)
        self.layout.addWidget(wgt)

        self.layout.addStretch(1)

        def insertSpace():
            spacer = Q.makeLabel("", 5)
            spacer.setContentsMargins(0, 5, 0, 0)
            grid.addWidget(spacer, row, 0, 1, 4)

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

        # RELAY FEE

        # Set string constants.
        self.lowStr = "low"
        self.defaultStr = "default"
        self.highStr = "high"

        # Set values that are considered low, default, and high.
        self.feeRates = {
            self.lowStr: 4000,
            self.defaultStr: int(DefaultRelayFeePerKb),
            self.highStr: 50000,
        }
        self.feeLvl = ""

        # Find the current level. Warn if the current level isn't one of the
        # three.
        for k, v in self.feeRates.items():
            if v == relayFee:
                self.feeLvl = k
                break
        else:
            log.warn(f"non standard relay fee set: {relayFee}")

        # Helper to check the current value.
        def setChecked(btn):
            if self.feeLvl == btn.text():
                btn.setChecked(True)

        row += 1
        insertSpace()
        row += 1
        lbl = Q.makeLabel("Relay Fee", 14, Q.ALIGN_LEFT)
        grid.addWidget(lbl, row, 0)
        self.feeLbl = lbl = Q.makeLabel("", 14, Q.ALIGN_LEFT)
        self.setFeeLbl(relayFee)
        grid.addWidget(lbl, row, 1)
        row += 1
        btn1 = QtWidgets.QRadioButton(self.lowStr)
        Q.setProperties(btn1, fontFamily="Roboto", fontSize=14)
        setChecked(btn1)
        btn1.toggled.connect(lambda: self.relayFeeChangeClicked(self.lowStr))
        btn2 = QtWidgets.QRadioButton(self.defaultStr)
        Q.setProperties(btn2, fontFamily="Roboto", fontSize=14)
        setChecked(btn2)
        btn2.toggled.connect(lambda: self.relayFeeChangeClicked(self.defaultStr))
        btn3 = QtWidgets.QRadioButton(self.highStr)
        Q.setProperties(btn3, fontFamily="Roboto", fontSize=14)
        setChecked(btn3)
        btn3.toggled.connect(lambda: self.relayFeeChangeClicked(self.highStr))
        wgt, _ = Q.makeRow(btn1, btn2, btn3)
        grid.addWidget(wgt, row, 0, 1, -1)

        self.layout.addStretch(1)

    def setFeeLbl(self, fee):
        """
        Set the displayed fee as atoms/byte.
        """
        self.feeLbl.setText(f"{fee//1000} atoms/byte")

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

    def relayFeeChangeClicked(self, feeLvl):
        """
        Qt slot connected to relay fee radio button clicked signal. Changes the
        relay fee to feeLvl.
        """
        if self.feeLvl == feeLvl:
            return
        self.feeLvl = feeLvl
        fee = self.feeRates[feeLvl]
        self.setRelayFee(fee)
        self.setFeeLbl(fee)
        log.info(f"relay fee changed to {fee} atoms/kb")
        app.appWindow.showSuccess(f"using {feeLvl} fees")


class NewAccountScreen(Screen):
    """
    A screen that displays a form to create a new account.
    """

    def __init__(self, ctl):
        """
        Args:
            ctl (AssetControl): The shared asset data.
        """
        super().__init__()
        self.canGoHome = True
        self.isPoppable = True
        self.acctMgr = ctl.acctMgr
        self.refresh = ctl.refreshAccounts
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
            if not cryptoKey:
                return
            try:
                acct = self.acctMgr.addAccount(cryptoKey, name)
                acct.unlock(cryptoKey)
                return acct
            except Exception as e:
                log.error(
                    f"exception encountered while adding account: {formatTraceback(e)}"
                )

        app.withCryptoKey(runCreateAcct, doneCreateAcct)


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
            "Copy these words carefully and keep them somewhere secure."
            " You will not have this chance again.",
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
        )  # The mnemonic screen is not persistent. Don't track this button.
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
        )  # The mnemonic screen is not persistent. Don't track this button.
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
                log.error(f"failed to create wallet: {formatTraceback(e)}")

        def withpw(pw):
            app.waitThread(create, finish, pw)

        app.getPassword(withpw, prompt="Create a wallet password")


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

        # Ticket price is a single row reading `Ticket Price: XX.YY DCR`.
        lbl = Q.makeLabel("Ticket Price: ", 16)
        self.lastPrice = None
        self.lastPriceStamp = 0
        self.ticketPrice = Q.makeLabel("--.--", 24, fontFamily="Roboto Bold")
        unit = Q.makeLabel("DCR", 16)
        priceWgt, _ = Q.makeRow(lbl, self.ticketPrice, unit)
        self.layout.addWidget(priceWgt)

        # Current holdings is a single row that reads `Currently staking X
        # tickets worth YY.ZZ DCR`.
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
        On SYNC_SIGNAL hide or show revoke button based on whether or not
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
                log.error(f"revoke tickets error: {formatTraceback(e)}")
                return False
            finally:
                app.emitSignal(ui.DONE_SIGNAL)

        withUnlockedAccount(self.account, revoke, self.revoked)

    def revoked(self, success):
        """
        revokeTickets callback. Prints success or failure to the screen.
        """
        if not success:
            app.appWindow.showError("revoke tickets finished with error")
            return
        n = self.revocableTicketsCount
        if n > 0:
            plural = "s" if n > 1 else ""
            app.appWindow.showSuccess(f"revoked {n} ticket{plural}")
            self.revocableTicketsCount = 0
        self.revokeBtn.hide()

    def setStats(self):
        """
        Get the current ticket stats and update the display.
        """
        acct = self.account
        stats = acct.ticketStats()
        self.ticketCount.setText(str(stats.count))
        self.ticketValue.setText(f"{stats.value / 1e8:.2f}")
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
                log.error(f"error fetching ticket price: {e}")
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
        self.ticketPrice.setText(f"{ticketPrice:.2f}")
        self.ticketPrice.setToolTip(f"{ticketPrice:.8f}")
        self.setBuyStats()

    def balanceSet(self, balance):
        """
        Connected to BALANCE_SIGNAL. Sets the balance and updates the display.

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
            app.appWindow.showError(f"can't afford {qty} tickets")

        def done(txs):
            if txs is None:
                return
            app.home()

        def do():
            return self.buyTickets(qty)

        def step():
            withUnlockedAccount(self.account, do, done)

        app.confirm(
            f"Are you sure you want to purchase {qty} ticket(s) for"
            f" {qty * self.lastPrice:.2f} DCR? Once purchased, these funds"
            " will be locked until your tickets vote or expire.",
            step,
        )

    def buyTickets(self, qty):
        """
        The second step in the sequence for a ticket purchase. Defer the hard
        work to the open Account.

        Args:
            qty (int): The number of tickets to purchase.

        Returns:
            list(msgtx.MsgTx): The purchased tickets.
        """
        txs = self.account.purchaseTickets(qty, self.lastPrice)
        if txs:
            app.home()
        app.appWindow.showSuccess(f"bought {qty} tickets")
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
        url = urlunsplit(
            ("https", f"{hostname}.dcrdata.org", f"/tx/{utxo.txid}", "", "")
        )
        openInBrowser(url)

    def addItems(self, liveTickets):
        """
        Add tickets to the live list.

        Args:
            liveTickets(dict[txid]UTXO): List of live tickets.
        """
        self.liveTickets = liveTickets
        self.ticketsWgt.clear()
        msgs = []
        for k, utxo in self.liveTickets.items():
            if utxo.height > -1:
                tail = f" @ height {utxo.height}"
            else:
                tail = " unconfirmed"
            msg = f"{k}... {tail}"
            msgs.append(msg)
        self.ticketsWgt.addItems(msgs)


class StakeStatsScreen(Screen):
    """
    A screen that shows network and ticket stats.
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
        self.liveTicketsScreen = LiveTicketsScreen()

        self.updatingLock = threading.Lock()

        # Live and immature tickets, viewable on dcrdata.
        self.liveTickets = {}

        # Keep track of last update and update if past LIFE.
        self.lastUpdated = time.time()
        self.LIFE = DCR.HOUR

        # Update stats on initial sync or if spent tickets have been updated.
        app.registerSignal(ui.SYNC_SIGNAL, self.setStats)
        app.registerSignal(ui.SPENT_TICKETS_SIGNAL, self.setStats)

        self.wgt.setMinimumWidth(400)
        self.wgt.setMinimumHeight(225)

        # Header and a button to show live tickets.
        lbl = Q.makeLabel("Staking", 18)
        self.liveTicketsListBtn = btn = app.getButton(TINY, "live tickets")
        btn.clicked.connect(lambda: app.appWindow.stack(self.liveTicketsScreen))
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, Q.STRETCH, btn)
        self.layout.addWidget(wgt)
        btn.hide()

        # Network statistics.
        lbl = Q.makeLabel("Network", 16)
        self.layout.addWidget(lbl, 0, Q.ALIGN_LEFT)

        lbl = Q.makeLabel("current height: ", 14)
        h = self.blkHeight = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, h)
        self.layout.addWidget(wgt)

        # Ticket prices.
        lbl = Q.makeLabel("current price: ", 14)
        lbl2 = Q.makeLabel("next price: ", 14)
        qty = self.stakeDiff = Q.makeLabel("", 14)
        qty2 = self.nextStakeDiff = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2)
        self.layout.addWidget(wgt)

        # Ticket pool and next blocks left in stake window.
        lbl = Q.makeLabel("ticket pool: ", 14)
        lbl2 = Q.makeLabel("next diff in: ", 14)
        qty = self.networkTickets = Q.makeLabel("", 14)
        qty2 = self.blocksLeft = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2)
        self.layout.addWidget(wgt)

        # Reward and total staked.
        lbl = Q.makeLabel("reward: ", 14)
        lbl2 = Q.makeLabel("total staked: ", 14)
        qty = self.stakebase = Q.makeLabel("", 14)
        qty2 = self.networkValue = Q.makeLabel("", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, qty2)
        self.layout.addWidget(wgt)

        # Lifetime user statistics.
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

        # Total staked and a button to show a list of live tickets.
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
        self.networkValue.setText(f"{tpinfo.value:.2f} dcr")
        blocksLeft = blksLeftStakeWindow(tpinfo.height, cfg.netParams)
        self.blocksLeft.setText(b(blocksLeft))
        cache = blockchain.subsidyCache
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
        # couple of links to aid in selecting a VSP.
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
                log.error(f"error retrieving stake pools: {e}")
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
        # TODO: Have 3 tinydecred network constants retrievable through cfg
        #   instead of checking the network config's Name attribute.
        if cfg.netParams.Name == "mainnet":
            self.pools = [
                p
                for p in pools
                if (tNow - p["LastUpdated"] < 86400) and (self.scorePool(p) > 95)
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
        self.score.setText(f"{self.scorePool(pool):.1f}%")
        self.fee.setText(f"{pool['PoolFees']:.1f}%")
        self.users.setText(str(pool["UserCountActive"]))

    def scorePool(self, pool):
        """
        Get the pool's performance score, as a float percentage.
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
                log.error(f"pool registration error: {formatTraceback(e)}")
                return False

        withUnlockedAccount(self.account, registerPool, self.callback)

    def showAll(self, e=None):
        """
        Connected to the "see all" button clicked signal. Open the
        decred.org VSP list in the browser.
        """
        openInBrowser("https://decred.org/vsp/")

    def linkClicked(self):
        """
        Callback from the clicked signal on the pool URL QLabel. Opens the
        pool's homepage in the user's browser.
        """
        openInBrowser(self.poolUrl.text())

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
        Go the next displayed page.
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
        self.pgNum.setText(f"{self.page + 1}/{len(self.pages)}")

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
        Set the user's current vote choice.
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
                        "unable to set vote: vote bit match not found"
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
                    log.error(f"error changing vote: {e}")
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
            acct (Account): A Decred account.
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
        self.pgNum.setText(f"{self.page + 1}/{len(self.pages)}")

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
            log.error(f"error fetching purchase info: {e}")
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
            penWidth (int): optional. The width of the line.
            pad (int): optional. Additional padding to place around the spinner.
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
        Create a QSvgWidget from the SVG file in the icons directory. The SVG
        will display at its designated pixel size if no dimensions are
        specified. If only one dimension is specified, the aspect ratio will be
        maintained for the other dimension.

        Args:
            path (str): Full path for non-tinywallet files. Otherwise, the
                basename of the file in the icons folder.
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


def withUnlockedAccount(acct, f, cb):
    """
    Run the provided function with the account open. If the account is not
    already open, the user will be prompted for their password and the account
    opened before the function is run.

    Args:
        acct (Account): A Decred account.
        f (func): A function to run with the account open.
        cb (func(x)): A callback to receive the return value from f.
    """
    if acct.isUnlocked():
        app.waitThread(f, cb)
        return

    def withkey(cryptoKey):
        if not cryptoKey:
            return
        try:
            acct.unlock(cryptoKey)
            return f()
        except Exception as e:
            log.warning(
                "exception encountered while performing"
                f" wallet action: {formatTraceback(e)}"
            )
            app.appWindow.showError("error")

    app.withCryptoKey(withkey, cb)
