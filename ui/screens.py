"""
Copyright (c) 2019, Brian Stafford
See LICENSE for detail
"""
import os
import time
import random
from PyQt5 import QtGui, QtCore, QtWidgets
from tinydecred import config
from tinydecred.ui import qutilities as Q, ui
from tinydecred.wallet.wallet import Wallet
from tinydecred.util import helpers
from tinydecred.pydecred import constants as DCR
from tinydecred.pydecred.vsp import VotingServiceProvider

UI_DIR = os.path.dirname(os.path.realpath(__file__))
log = helpers.getLogger("APPUI") # , logLvl=0)
cfg = config.load()

# Some commonly used ui constants.
TINY = ui.TINY
SMALL = ui.SMALL
MEDIUM = ui.MEDIUM
LARGE = ui.LARGE

# A key to identify the screen fade in animation.
FADE_IN_ANIMATION = "fadeinanimation"

formatTraceback = helpers.formatTraceback

def pixmapFromSvg(filename, w, h):
    """
    Create a QPixmap from the svg file in the icons directory.

    Args:
        filename (str): The filename without directory.
        w (int): Pixel width of the resulting pixmap.
        h (int): Pixel height of the resulting pixmap.

    Returns:
        QPixmap: A sized pixmap created from the scaled SVG file.
    """
    return QtGui.QIcon(os.path.join(UI_DIR, "icons", filename)).pixmap(w, h)

class TinyDialog(QtWidgets.QFrame):
    """
    TinyDialog is a widget for handling Screen instances. This is the primary
    window of the TinyDecred application. It has a fixed (tiny!) size.
    """
    maxWidth = 525
    maxHeight = 375
    targetPadding = 15
    popSig = QtCore.pyqtSignal(Q.PyObj)
    stackSig = QtCore.pyqtSignal(Q.PyObj)
    topMenuHeight = 26
    successSig = QtCore.pyqtSignal(str)
    errorSig = QtCore.pyqtSignal(str)
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__()
        self.app = app
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.popSig.connect(self.pop_)
        self.pop = lambda w=None: self.popSig.emit(w)
        self.stackSig.connect(self.stack_)
        self.stack = lambda p: self.stackSig.emit(p)

        # Set the width and height explicitly. Keep it tiny.
        screenGeo = app.qApp.primaryScreen().availableGeometry()
        self.w = self.maxWidth if screenGeo.width() >= self.maxWidth else screenGeo.width()
        self.h =  self.maxHeight if screenGeo.height() >= self.maxHeight else screenGeo.height()
        availPadX = (screenGeo.width() - self.w) / 2
        self.padX = self.targetPadding if availPadX >= self.targetPadding else availPadX
        self.setGeometry(
            screenGeo.x() + screenGeo.width() - self.w - self.padX,
            screenGeo.y() + screenGeo.height() - self.h,
            self.w,
            self.h
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
        self.working = Spinner(self.app, 20, 3, 0)
        self.working.setVisible(False)
        self.working.setFixedSize(20,20)
        menuLayout.addWidget(Q.pad(self.working, 3, 3, 3, 3), 0, Q.ALIGN_CENTER)
        app.registerSignal(ui.WORKING_SIGNAL, lambda: self.working.setVisible(True))
        app.registerSignal(ui.DONE_SIGNAL, lambda: self.working.setVisible(False))

        # If enabled by a Screen instance, the user can navigate back to the
        # previous screen.
        self.backIcon = ClickyLabel(self.backClicked)
        self.backIcon.setPixmap(pixmapFromSvg("back.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.backIcon, 3, 3, 3, 3))

        # If enabled by a Screen instance, the user can navigate directly to
        # the home screen.
        self.homeIcon = ClickyLabel(self.homeClicked)
        self.homeIcon.setPixmap(pixmapFromSvg("home.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.homeIcon, 3, 3, 3, 3))

        # Separate the left and right sub-menus.
        menuLayout.addStretch(1)

        self.closeIcon = ClickyLabel(self.closeClicked)
        self.closeIcon.setPixmap(pixmapFromSvg("x.svg", 20, 20))
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
        self.textFlags = QtCore.Qt.TextWordWrap | QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop
    def showEvent(self, e):
        # geo = self.app.sysTray.geometry()
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
        User has clicked close. Since TinyDecred is a system tray application,
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

            column = QtCore.QRect(0, 0, fullWidth - 4*pad, 10000)

            textBox = painter.boundingRect(
                column,
                self.textFlags,
                self.msg
            )

            lrPad = (fullWidth - textBox.width()) / 2 - pad

            outerWidth = textBox.width() + 2*pad
            outerHeight = textBox.height() + 2*pad

            w = textBox.width() + 2*pad
            pTop = TinyDialog.topMenuHeight + pad

            painter.fillRect(lrPad, pTop, outerWidth, outerHeight, self.bgBrush)
            painter.drawRect(lrPad, pTop, outerWidth, outerHeight)
            painter.drawText(
                QtCore.QRect(lrPad + pad, pTop + pad, w, 10000),
                self.textFlags,
                self.msg
            )

class Screen(QtWidgets.QWidget):
    """
    Screen is all the user sees in the main application window. All UI widgets
    should inherit Screen.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__()
        self.app = app
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
            self.animations[FADE_IN_ANIMATION] = a = QtCore.QPropertyAnimation(effect, b"opacity")
            a.setDuration(550)
            a.setStartValue(0)
            a.setEndValue(1)
            a.setEasingCurve(QtCore.QEasingCurve.OutQuad)
            self.setGraphicsEffect(effect)
        else:
            self.animations.pop(FADE_IN_ANIMATION, None)

class HomeScreen(Screen):
    """
    The standard home screen for a TinyDecred account.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.app = app

        # The TinyDialog won't allow popping of the bottom screen anyway.
        self.isPoppable = False
        self.canGoHome = False
        self.ticketStats = None
        self.balance = None
        self.stakeScreen = StakingScreen(app)

        # Update the home screen when the balance signal is received.
        app.registerSignal(ui.BALANCE_SIGNAL, self.balanceUpdated)
        app.registerSignal(ui.SYNC_SIGNAL, self.setTicketStats)

        layout = self.layout
        layout.setAlignment(Q.ALIGN_LEFT)
        layout.setSpacing(50)

        # Display the current account balance.
        logo = QtWidgets.QLabel()
        logo.setPixmap(pixmapFromSvg(DCR.LOGO, 40, 40))

        self.totalBalance = b = ClickyLabel(self.balanceClicked, "0.00")
        Q.setProperties(b, fontFamily="Roboto-Bold", fontSize=36)
        self.totalUnit = Q.makeLabel("DCR", 18, color="#777777")
        self.totalUnit.setContentsMargins(0, 7, 0, 0)

        self.availBalance = ClickyLabel(self.balanceClicked, "0.00 spendable")
        Q.setProperties(self.availBalance, fontSize=15)

        self.statsLbl = Q.makeLabel("", 15)

        tot, totLyt = Q.makeSeries(Q.HORIZONTAL,
            self.totalBalance,
            self.totalUnit,
        )

        bals, balsLyt = Q.makeSeries(Q.VERTICAL,
            tot,
            self.availBalance,
            self.statsLbl,
            align=Q.ALIGN_RIGHT,
        )

        logoCol, logoLyt = Q.makeSeries(Q.VERTICAL,
            logo,
            Q.makeLabel("Decred", fontSize=18, color="#777777"),
            align=Q.ALIGN_LEFT,
        )

        row, rowLyt = Q.makeSeries(Q.HORIZONTAL,
            logoCol,
            Q.STRETCH,
            bals,
        )

        layout.addWidget(row)

        # Create a row to hold an address.
        addrLbl = Q.makeLabel("Address", 14, color="#777777")
        new = ClickyLabel(self.newAddressClicked, "+new")
        Q.setProperties(new, color="#777777")
        self.address = Q.makeLabel("", 18, fontFamily="RobotoMono-Bold")
        self.address.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

        header, headerLyt = Q.makeSeries(Q.HORIZONTAL,
            addrLbl,
            Q.STRETCH,
            new,
        )

        col, colLyt = Q.makeSeries(Q.VERTICAL,
            header,
            self.address,
        )

        layout.addWidget(col)

        # Option buttons.
        opts, optsLyt = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        layout.addWidget(opts, 1)

        # Send DCR.
        spend = app.getButton(SMALL, "Send DCR")
        spend.setMinimumWidth(110)
        spend.clicked.connect(self.spendClicked)
        optsLyt.addWidget(spend, 0, 0, Q.ALIGN_LEFT)

        self.spinner = Spinner(self.app, 35)
        optsLyt.addWidget(self.spinner, 0, 1, Q.ALIGN_RIGHT)

        # Open staking window. Button is initally hidden until sync is complete.
        self.stakeBttn = btn = app.getButton(SMALL, "Staking")
        btn.setVisible(False)
        btn.setMinimumWidth(110)
        btn.clicked.connect(self.openStaking)
        optsLyt.addWidget(btn, 0, 1, Q.ALIGN_RIGHT)

        # Navigate to the settings screen.
        # settings = app.getButton(SMALL, "Settings")
        # settings.setMinimumWidth(110)
        # settings.clicked.connect(self.settingsClicked)

        optsLyt.addWidget(QtWidgets.QWidget(), 0, 1, Q.ALIGN_RIGHT)
        optsLyt.setColumnStretch(0, 1)
        optsLyt.setColumnStretch(1, 1)
        optsLyt.setSpacing(35)
    def newAddressClicked(self):
        """
        Generate and display a new address. User password required.
        """
        app = self.app
        def addr(wallet):
            return wallet.getNewAddress()
        app.withUnlockedWallet(addr, self.setNewAddress)
    def setNewAddress(self, address):
        """
        Callback for newAddressClicked. Sets the displayed address.
        """
        if address:
            self.address.setText(address)
    def showEvent(self, e):
        """
        When this screen is shown, set the payment address.
        """
        app = self.app
        if app.wallet:
            address = app.wallet.currentAddress()
            self.address.setText(address)
    def balanceClicked(self):
        """
        Show the user a basic balance breakdown.
        """
        log.info("balance clicked")
    def balanceUpdated(self, bal):
        """
        A BALANCE_SIGNAL receiver that updates the displayed balance.
        """
        dcr = bal.total*1e-8 // 0.01 * 0.01
        availStr = "%.8f" % (bal.available*1e-8, )
        self.totalBalance.setText("{0:,.2f}".format(dcr))
        self.totalBalance.setToolTip("%.8f" % dcr)
        self.availBalance.setText("%s spendable" % availStr.rstrip('0').rstrip('.'))
        self.balance = bal
        if self.ticketStats:
            self.setTicketStats()
    def setTicketStats(self):
        """
        Set the staking statistics.
        """
        acct = self.app.wallet.selectedAccount
        balance = self.balance
        stats = acct.ticketStats()
        if stats and balance and balance.total > 0:
            self.spinner.setVisible(False)
            self.stakeBttn.setVisible(True)
            self.statsLbl.setText("%s%% staked" % helpers.formatNumber(stats.value/balance.total*100))
            self.ticketStats = stats
    def spendClicked(self, e=None):
        """
        Display a form to send funds to an address. A Qt Slot, but any event
        parameter is ignored.
        """
        self.app.appWindow.stack(self.app.sendScreen)
    def openStaking(self, e=None):
        """
        Display the staking window.
        """
        self.app.appWindow.stack(self.stakeScreen)
    def settingsClicked(self, e):
        log.debug("settings clicked")

class PasswordDialog(Screen):
    """
    PasswordDialog is a simple form for getting a user-supplied password.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        content, mainLayout = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.layout.addWidget(Q.pad(content, 20, 20, 20, 20))
        mainLayout.setSpacing(10)
        self.isPoppable = True
        self.canGoHome = False

        mainLayout.addWidget(QtWidgets.QLabel("password"))
        pw = self.pwInput = QtWidgets.QLineEdit()
        mainLayout.addWidget(pw)
        pw.setEchoMode(QtWidgets.QLineEdit.Password)
        pw.setMinimumWidth(250)
        pw.returnPressed.connect(self.pwSubmit)
        self.callback = lambda p: None

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
    def pwSubmit(self):
        """
        Qt Slot which submits the password field value to the current callback.
        """
        self.callback(self.pwInput.text())
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
        self.callback = lambda p, a=args, k=kwargs: callback(p, *a, **k)
        return self

class ClickyLabel(QtWidgets.QLabel):
    """
    Qt does not have a `clicked` signal on a QLabel, so one is implemented here.
    """
    def __init__(self, callback, *a):
        """
        Args:
            callback (func): A callback function to be called when the label
                is clicked.
            *a: Any additional arguments are passed directly to the parent
                QLabel constructor.
        """
        super().__init__(*a)
        self.mouseDown = False
        self.callback = callback
        self.setCursor(QtCore.Qt.PointingHandCursor)
    def mousePressEvent(self, e):
        if e.button() == QtCore.Qt.LeftButton:
            self.mouseDown = True
    def mouseReleaseEvent(self, e):
        if e.button() == QtCore.Qt.LeftButton and self.mouseDown:
            self.callback()
    def mouseMoveEvent(self, e):
        """
        When the mouse is moved, check whether the mouse is within the bounds of
        the label. If not, set mouseDown to False. The user must click and
        release without the mouse leaving the label to trigger the callback.
        """
        if self.mouseDown == False:
            return
        qSize = self.size()
        ePos = e.pos()
        x, y = ePos.x(), ePos.y()
        if x < 0 or y < 0 or x > qSize.width() or y > qSize.height():
            self.mouseDown = False

class InitializationScreen(Screen):
    """
    A screen shown when no wallet file is detected. This screen offers options
    for creating a new wallet or loading an existing wallet.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.canGoHome = False
        self.layout.setSpacing(20)
        lbl = Q.makeLabel("Welcome!", 26, fontFamily="Roboto-Medium")
        self.layout.addWidget(lbl)
        self.layout.addWidget(Q.makeLabel("How would you like to begin?", 16))

        # Create a new wallet.
        self.initBttn = app.getButton(SMALL, "create wallet")
        self.layout.addWidget(self.initBttn)
        self.initBttn.clicked.connect(self.initClicked)

        # Load a TinyDecred wallet file.
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
        self.app.getPassword(self.initPasswordCallback)
    def initPasswordCallback(self, pw):
        """
        Create a wallet encrypted with the user-supplied password. The wallet
        will be open to the default account, but will not be locked for use.

        Args:
            pw (str): A user supplied password string.
        """
        # either way, pop the password window
        app = self.app
        if pw is None or pw == "":
            app.appWindow.showError("you must enter a password to create a wallet")
        else:
            def create():
                try:
                    app.dcrdata.connect()
                    app.emitSignal(ui.BLOCKCHAIN_CONNECTED)
                    words, wallet = Wallet.create(app.walletFilename(), pw, cfg.net)
                    wallet.open(0, pw, app.dcrdata, app.blockchainSignals)
                    return words, wallet
                except Exception as e:
                    log.error("failed to create wallet: %s" % formatTraceback(e))
            app.waitThread(create, self.finishInit)
    def finishInit(self, ret):
        """
        The callback from new wallet creation.
        """
        app = self.app
        if ret:
            words, wallet = ret
            app.saveSettings()
            app.setWallet(wallet)
            app.home()
            app.showMnemonics(words)
        else:
            app.appWindow.showError("failed to create wallet")
    def loadClicked(self):
        """
        The user has selected the "load from from" option. Prompt for a file
        location and load the wallet.
        """
        app = self.app
        fd = QtWidgets.QFileDialog(self, "select wallet file")
        fd.setViewMode(QtWidgets.QFileDialog.Detail)
        qdir = QtCore.QDir
        fd.setFilter(qdir.Dirs | qdir.Files | qdir.NoDotAndDotDot | qdir.Hidden)
        if (fd.exec_()):
            fileNames = fd.selectedFiles()
            if len(fileNames) != 1:
                log.error("More than 1 file selected for importing")
                raise Exception("More than 1 file selected for importing")
        else:
            raise Exception("no file selected")
        walletPath = fileNames[0]
        log.debug('loading wallet from %r' % walletPath)
        if walletPath == "":
            app.appWindow.showError("no file selected")
        elif not os.path.isfile(walletPath):
            log.error("no file found at %s" % walletPath)
            app.showMessaage("file error. try again")
        else:
            def load(pw, userPath):
                if pw is None or pw == "":
                    app.appWindow.showError("you must enter the password for this wallet")
                else:
                    try:
                        appWalletPath = app.walletFilename()
                        app.dcrdata.connect()
                        app.emitSignal(ui.BLOCKCHAIN_CONNECTED)
                        wallet = Wallet.openFile(userPath, pw)
                        wallet.open(0, pw, app.dcrdata, app.blockchainSignals)
                        # Save the wallet to the standard location.
                        wallet.path = appWalletPath
                        wallet.save()
                        app.setWallet(wallet)
                        app.home()
                    except Exception as e:
                        log.warning("exception encountered while attempting to open wallet: %s" % formatTraceback(e))
                        app.appWindow.showError("error opening this wallet? password correct? correct network?")
            app.getPassword(load, walletPath)
    def restoreClicked(self):
        """
        User has selected to generate a wallet from a mnemonic seed.
        """
        restoreScreen = MnemonicRestorer(self.app)
        self.app.appWindow.stack(restoreScreen)

def sendToAddress(wallet, val, addr):
    """
    Send the value in DCR to the provided address.
    """
    try:
        return wallet.sendToAddress(int(round(val*1e8)), addr) # raw transaction
    except Exception as e:
        log.error("failed to send: %s" % formatTraceback(e))
    return False

class SendScreen(Screen):
    """
    A screen that displays a form to send funds to an address.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.canGoHome = True
        self.isPoppable = True
        layout = self.layout
        layout.setSpacing(25)

        layout.addWidget(Q.makeLabel("Sending Decred", 25, fontFamily="Roboto-Medium"))

        # A field to enter the value to send, in asset units (not atoms).
        col, colLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        layout.addWidget(col)
        colLyt.addWidget(Q.makeLabel("how much?", 16, color="#777777"), 0, Q.ALIGN_LEFT)
        self.valField = vf = QtWidgets.QLineEdit()
        self.valField.setFixedWidth(175)
        colLyt.addWidget(vf, 0, Q.ALIGN_LEFT)

        # A file to enter an address to send funds to.
        col, colLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        layout.addWidget(col)
        colLyt.addWidget(Q.makeLabel("to address", 16, color="#777777"), 0, Q.ALIGN_LEFT)
        self.addressField = af = QtWidgets.QLineEdit()
        Q.setProperties(af, fontSize=14)
        af.setFixedWidth(350)
        colLyt.addWidget(af)

        # The user must click the send button. No return button from QLineEdit.
        send = app.getButton(SMALL, "send")
        layout.addWidget(send, 0, Q.ALIGN_RIGHT)
        send.setFixedWidth(125)
        send.clicked.connect(self.sendClicked)
    def sendClicked(self, e):
        """
        Qt slot for clicked signal from submit button. Send the amount specified
        to the address specified.
        """
        val = float(self.valField.text())
        address = self.addressField.text()
        log.debug("sending %f to %s" % (val, address))
        self.app.withUnlockedWallet(sendToAddress, self.sent, val, address)
    def sent(self, res):
        """
        Receives the result of sending funds.

        Args:
            res (bool): Success status of the send operation.
        """
        app = self.app
        if res:
            app.home()
            app.appWindow.showSuccess("sent")
        else:
            app.appWindow.showError("transaction error")



class WaitingScreen(Screen):
    """
    Waiting screen displays a Spinner.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.isPoppable = False
        self.canGoHome = False
        self.spinner = Spinner(self.app, 60)
        self.layout.addWidget(self.spinner)

class MnemonicScreen(Screen):
    """
    Display the mnemonic seed from wallet creation.
    """
    def __init__(self, app, words):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.isPoppable = True
        self.canGoHome = True
        self.wgt.setMaximumWidth(320)
        self.layout.setSpacing(10)

        # Some instructions for the user. It is critical that they copy the seed
        # now, as it can't be regenerated.
        self.lbl = Q.makeLabel(
            "Copy these words carefully and keep them somewhere secure. "
            "You will not have this chance again.",
            16)
        self.lbl.setWordWrap(True)
        self.layout.addWidget(self.lbl)

        # Create a label to hold the actual seed.
        lbl = QtWidgets.QLabel(" ".join(words))
        Q.setProperties(lbl, fontSize=15)
        lbl.setMaximumWidth(500)
        lbl.setStyleSheet("QLabel{border: 1px solid #777777; padding: 10px;}")
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard)
        row, lyt = Q.makeWidget(QtWidgets.QWidget, "horizontal")
        self.layout.addWidget(row)
        lyt.addStretch(1)
        lyt.addWidget(lbl)
        lyt.addStretch(1)

        # A button that must be clicked to pop the screen.
        button = app.getButton(SMALL, "all done", tracked=False) # the mnemonic screen is not persistent. Don't track this button.
        self.layout.addWidget(button)
        button.clicked.connect(self.clearAndClose)
    def clearAndClose(self, e):
        """
        Pop this screen.
        """
        self.lbl.setText("")
        self.app.appWindow.pop(self)

class MnemonicRestorer(Screen):
    """
    A screen with a simple form for entering a mnemnic seed from which to
    generate a wallet.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.isPoppable = True
        self.canGoHome = False
        self.wgt.setMaximumWidth(320)
        self.layout.setSpacing(10)

        # Some instructions for the user.
        self.lbl = Q.makeLabel("Enter your mnemonic seed here. Separate words with whitespace.", 18)
        self.lbl.setWordWrap(True)
        self.layout.addWidget(self.lbl)

        # A field to enter the seed words.
        self.edit = edit = QtWidgets.QTextEdit()
        edit.setAcceptRichText(False)
        edit.setMaximumWidth(300)
        edit.setFixedHeight(225)
        edit.setStyleSheet("QLabel{border: 1px solid #777777; padding: 10px;}")
        # edit.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard)
        row, lyt = Q.makeWidget(QtWidgets.QWidget, "horizontal")
        self.layout.addWidget(row)
        lyt.addStretch(1)
        lyt.addWidget(edit)
        lyt.addStretch(1)

        # The user must click the button to submit.
        button = app.getButton(SMALL, "OK", tracked=False) # the mnemonic screen is not persistent. Don't track this button.
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
        app = self.app
        words = self.edit.toPlainText().strip().split()
        if not words:
            app.appWindow.showError("enter words to create a wallet")
        else:
            def pwcb(pw, words):
                if pw:
                    def create():
                        try:
                            app.dcrdata.connect()
                            app.emitSignal(ui.BLOCKCHAIN_CONNECTED)
                            wallet = Wallet.createFromMnemonic(words, app.walletFilename(), pw, cfg.net)
                            wallet.open(0, pw, app.dcrdata, app.blockchainSignals)
                            return wallet
                        except Exception as e:
                            log.error("failed to create wallet: %s" % formatTraceback(e))
                    app.waitThread(create, self.finishCreation)
                else:
                    app.appWindow.showError("must enter a password to recreate the wallet")
            app.getPassword(pwcb, words)
    def finishCreation(self, ret):
        """
        The callback from new wallet creation.
        """
        app = self.app
        if ret:
            wallet = ret
            app.saveSettings()
            app.setWallet(wallet)
            app.home()
        else:
            app.appWindow.showError("failed to create wallet")
    def walletCreationComplete(self, wallet):
        """
        Receives the result from wallet creation.

        Args:
            ret (None or Wallet): The wallet if successfully created. None if
                failed.
        """
        app = self.app
        if wallet:
            app.saveSettings()
            app.setWallet(wallet)
            app.home()
        else:
            app.appWindow.showError("failed to create wallet")

class StakingScreen(Screen):
    """
    A screen with a form to purchase tickets.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.isPoppable = True
        self.canGoHome = True
        self.layout.setSpacing(20)
        self.poolScreen = PoolScreen(app, self.poolAuthed)
        self.accountScreen = PoolAccountScreen(app, self.poolScreen)
        self.balance = None
        self.wgt.setContentsMargins(5, 5, 5, 5)
        self.wgt.setMinimumWidth(400)
        self.blockchain = app.dcrdata

        # Register for a few key signals.
        self.app.registerSignal(ui.BLOCKCHAIN_CONNECTED, self.blockchainConnected)
        self.app.registerSignal(ui.BALANCE_SIGNAL, self.balanceSet)
        self.app.registerSignal(ui.SYNC_SIGNAL, self.setStats)

        # ticket price is a single row reading `Ticket Price: XX.YY DCR`.
        lbl = Q.makeLabel("Ticket Price: ", 16)
        self.lastPrice = None
        self.lastPriceStamp = 0
        self.ticketPrice = Q.makeLabel("--.--", 24, fontFamily="Roboto-Bold")
        unit = Q.makeLabel("DCR", 16)
        priceWgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, self.ticketPrice, unit)
        self.layout.addWidget(priceWgt)

        # Current holdings is a single row that reads `Currently staking X
        # tickets worth YY.ZZ DCR`
        lbl = Q.makeLabel("Currently staking", 14)
        self.ticketCount = Q.makeLabel("", 18, fontFamily="Roboto-Bold")
        lbl2 = Q.makeLabel("tickets worth", 14)
        self.ticketValue = Q.makeLabel("", 18, fontFamily="Roboto-Bold")
        unit = Q.makeLabel("DCR", 14)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, self.ticketCount, lbl2, self.ticketValue, unit)
        self.layout.addWidget(wgt)

        # Affordability. A row that reads `You can afford X tickets`
        lbl = Q.makeLabel("You can afford ", 14)
        self.affordLbl = Q.makeLabel(" ", 17, fontFamily="Roboto-Bold")
        lbl2 = Q.makeLabel("tickets", 14)
        affordWgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, self.affordLbl, lbl2)
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
        purchaseWgt, lyt = Q.makeSeries(Q.HORIZONTAL, lbl, qty, lbl2, Q.STRETCH, btn)
        lyt.setContentsMargins(10, 10, 10, 10)
        Q.addDropShadow(purchaseWgt)
        self.layout.addWidget(purchaseWgt)

        # Navigate to account screen, to choose or add a different VSP account.
        self.currentPool = Q.makeLabel("", 15)
        lbl2 = ClickyLabel(self.stackAccounts, "change")
        Q.setProperties(lbl2, underline=True, fontSize=15)
        Q.addHoverColor(lbl2, "#f5ffff")
        wgt, lyt = Q.makeSeries(Q.HORIZONTAL, self.currentPool, Q.STRETCH, lbl2)
        lyt.setContentsMargins(0, 10, 0, 0)
        self.layout.addWidget(wgt)

    def stacked(self):
        """
        stacked is called on screens when stacked by the TinyDialog.
        """
        acct = self.app.wallet.selectedAccount
        if not acct.hasPool():
            self.app.appWindow.pop(self)
            self.app.appWindow.stack(self.poolScreen)

    def stackAccounts(self):
        self.app.appWindow.stack(self.accountScreen)
    def setStats(self):
        """
        Get the current ticket stats and update the display.
        """
        acct = self.app.wallet.selectedAccount
        stats = acct.ticketStats()
        self.ticketCount.setText(str(stats.count))
        self.ticketValue.setText("%.2f" % (stats.value/1e8))
        stakePool = acct.stakePool()
        if stakePool:
            self.currentPool.setText(stakePool.url)

    def blockchainConnected(self):
        """
        Connected to the BLOCKCHAIN_CONNECTED signal. Updates the current
        ticket price.
        """
        self.app.makeThread(getTicketPrice, self.ticketPriceCB, self.blockchain)

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

    def setBuyStats(self):
        """
        Update the display of the current affordability stats.
        """
        if self.balance and self.lastPrice:
            self.affordLbl.setText(str(int(self.balance.available/1e8/self.lastPrice)))

    def buyClicked(self, e=None):
        """
        Connected to the "Buy Now" button clicked signal. Initializes the ticket
        purchase routine.
        """
        qtyStr = self.ticketQty.text()
        if not qtyStr or qtyStr == "":
            self.app.appWindow.showError("can't purchase zero tickets")
            return
        qty = int(qtyStr)
        if qty > self.balance.available/1e8/self.lastPrice:
            self.app.appWindow.showError("can't afford %d tickets" % qty)
        def step():
            self.app.withUnlockedWallet(self.buyTickets, self.ticketsBought, qty)
        self.app.confirm("Are you sure you want to purchase %d ticket(s) for %.2f DCR? "
                         "Once purchased, these funds will be locked until your tickets vote or expire."
                         % (qty, qty*self.lastPrice),
                         step)
    def buyTickets(self, wallet, qty):
        """
        The second step in the sequence for a ticket purchase. Defer the hard
        work to the open Account.

        Args:
            wallet (Wallet): The open wallet.
            qty (int): The number of tickets to purchase.

        Returns:
            list(msgtx.MsgTx): The purchased tickets.
        """
        tip = self.blockchain.tip["height"]
        acct = wallet.openAccount
        txs = acct.purchaseTickets(qty, self.lastPrice)
        if txs:
            wallet.signals.balance(acct.calcBalance(tip))
            self.app.home()
        self.app.appWindow.showSuccess("bought %s tickets" % qty)
        wallet.save()
        return txs
    def ticketsBought(self, res):
        """
        The final callback from a ticket purchase. If res evaluates True, it
        should be a list of purchased tickets.
        """
        if not res:
            self.app.appWindow.showError("error purchasing tickets")
            self.app.home()
    def poolAuthed(self, res):
        """
        The callback from the PoolScreen when a pool is added. If res evaluates
        True, the pool was successfully authorized.
        """
        if not res:
            # The pool screen handles error notifications.
            self.app.home()
        window = self.app.appWindow
        window.pop(self.poolScreen)
        window.stack(self)

class PoolScreen(Screen):
    def __init__(self, app, callback):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
            callback (function): A function to call when a pool is succesfully
                validated.
        """
        super().__init__(app)
        self.isPoppable = True
        self.canGoHome = True
        self.callback = callback
        self.pools = []
        self.poolIdx = -1
        self.app.registerSignal(ui.BLOCKCHAIN_CONNECTED, self.getPools)
        self.wgt.setMinimumWidth(400)
        self.wgt.setContentsMargins(15, 0, 15, 0)

        # After the header, there are two rows that make up the form. The first
        # row is a QLineEdit and a button that takes the pool URL. The second
        # row is a slightly larger QLineEdit for the API key.
        lbl = Q.makeLabel("Add a voting service provider", 16)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, lbl, Q.STRETCH)
        self.layout.addWidget(wgt)
        self.poolIp = edit = QtWidgets.QLineEdit()
        edit.setPlaceholderText("e.g. https://anothervsp.com")
        edit.returnPressed.connect(self.authPool)
        btn = app.getButton(SMALL, "Add")
        btn.clicked.connect(self.authPool)
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, self.poolIp, btn)
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
        self.poolUrl = Q.makeLabel("", 16, a=l, fontFamily="Roboto-Medium")
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
        stats, _ = Q.makeSeries( Q.HORIZONTAL,
            self.poolLink, Q.STRETCH,
            scoreLbl, self.score, Q.STRETCH,
            feeLbl, self.fee, Q.STRETCH,
            usersLbl, self.users
        )
        poolWgt, lyt = Q.makeSeries(Q.VERTICAL, self.poolUrl, stats)
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
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, btn1, Q.STRETCH, btn2)
        self.layout.addWidget(wgt)

    def getPools(self):
        """
        Get the current master list of VSPs from decred.org.
        """
        net = self.app.dcrdata.params
        def get():
            try:
                return VotingServiceProvider.providers(net)
            except Exception as e:
                log.error("error retrieving stake pools: %s" % e)
                return False
        self.app.makeThread(get, self.setPools)

    def setPools(self, pools):
        """
        Cache the list of stake pools from decred.org, and pick one to display.

        Args:
            pools (list(object)): The freshly-decoded-from-JSON stake pools.
        """
        if not pools:
            return
        self.pools = pools
        tNow = int(time.time())
        # only save pools updated within the last day
        self.pools = [p for p in pools if tNow - p["LastUpdated"] < 86400 and self.scorePool(p) > 95]
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
            log.warn("no stake pools returned from server")
        lastIdx = self.poolIdx
        if count == 1:
            self.poolIdx = 0
        else:
            # pick random elements until the index changes
            while self.poolIdx == lastIdx:
                self.poolIdx = random.randint(0, count-1)
        pool = pools[self.poolIdx]
        self.poolUrl.setText(pool["URL"])
        self.score.setText("%.1f%%" % self.scorePool(pool))
        self.fee.setText("%.1f%%" % pool["PoolFees"])
        self.users.setText(str(pool["UserCountActive"]))

    def scorePool(self, pool):
        """
        Get the pools performance score, as a float percentage.
        """
        return pool["Voted"]/(pool["Voted"]+pool["Missed"])*100

    def authPool(self):
        """
        Connected to the "Add" button clicked signal. Attempts to authorize the
        user-specified pool and API key.
        """
        url = self.poolIp.text()
        app = self.app
        err = app.appWindow.showError
        if not url:
            err("empty address")
            return
        if not url.startswith("http://") and not url.startswith("https://"):
            err("invalid pool address: %s" % url)
            return
        apiKey = self.keyIp.text()
        if not apiKey:
            err("empty API key")
            return
        pool = VotingServiceProvider(url, apiKey)
        def registerPool(wallet):
            try:
                addr = wallet.openAccount.votingAddress()
                pool.authorize(addr, cfg.net)
                app.appWindow.showSuccess("pool authorized")
                wallet.openAccount.setPool(pool)
                wallet.save()
                return True
            except Exception as e:
                err("pool authorization failed")
                log.error("pool registration error: %s" % formatTraceback(e))
                return False
        app.withUnlockedWallet(registerPool, self.callback)
    def showAll(self, e=None):
        """
        Connected to the "see all" button clicked signal. Open the fu
        decred.org VSP list in the browser.
        """
        QtGui.QDesktopServices.openUrl(QtCore.QUrl("https://decred.org/vsp/"))
    def linkClicked(self):
        """
        Callback from the clicked signal on the pool URL QLabel. Opens the
        pool's homepage in the users browser.
        """
        QtGui.QDesktopServices.openUrl(QtCore.QUrl(self.poolUrl.text()))
    def poolClicked(self):
        """
        Callback from the clicked signal on the try-this-pool widget. Sets the
        url in the QLineEdit.
        """
        self.poolIp.setText(self.poolUrl.text())

class PoolAccountScreen(Screen):
    """
    A screen that lists currently known VSP accounts, and allows adding new
    accounts or changing the selected account.
    """
    def __init__(self, app, poolScreen):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.isPoppable = True
        self.canGoHome = True

        self.pages = []
        self.page = 0

        self.poolScreen = poolScreen
        self.app.registerSignal(ui.SYNC_SIGNAL, self.setPools)
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

        self.pagination, _ = Q.makeSeries(Q.HORIZONTAL,
            self.prevPg,
            Q.STRETCH,
            self.pgNum,
            Q.STRETCH,
            self.nextPg)
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
        self.pgNum.setText("%d/%d" % (self.page+1, len(self.pages)))
    def setPools(self):
        """
        Reset the stake pools list from that active account and set the first
        page.
        """
        acct = self.app.wallet.selectedAccount
        if not acct:
            log.error("no account selected")
        pools = acct.stakePools
        if len(pools) == 0:
            return
        self.pages = [pools[i*2:i*2+2] for i in range((len(pools)+1)//2)]
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
            wgt, lyt = Q.makeSeries(Q.VERTICAL,
                urlLbl, addrLbl, align=Q.ALIGN_LEFT)
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
        self.app.appWindow.showSuccess("new pool selected")
        self.app.wallet.selectedAccount.setPool(pool)
        self.setPools()

    def addClicked(self, e=None):
        """
        The clicked slot for the add pool button. Stacks the pool screen.
        """
        self.app.appWindow.pop(self)
        self.app.appWindow.stack(self.poolScreen)

class ConfirmScreen(Screen):
    """
    A screen that displays a custom prompt and calls a callback function
    conditionally on user affirmation. The two available buttons say "ok" and
    "no". Clicking "ok" triggers the callback. Clicking "no" simply pops this
    Screen.
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
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
        wgt, _ = Q.makeSeries(Q.HORIZONTAL, Q.STRETCH, stop, Q.STRETCH, go, Q.STRETCH)
        wgt.setContentsMargins(0, 20, 0, 0)
        self.layout.addWidget(wgt)
    def withPurpose(self, prompt, callback):
        """
        Set the prompts and callback and return self.

        Args:
            prompt (string): The prompt for the users.
            callback (function): The function to call when the user clicks "ok".

        Returns:
            ConfirmScreen: This instance. Useful for using a patter like
                app.appWindow.stack(confirmScreen.withPurpose("go ahead?", callbackFunc))
        """
        self.prompt.setText(prompt)
        self.callback = callback
        return self
    def stopClicked(self, e=None):
        """
        The user has clicked "no". Just pop this screen.
        """
        self.app.appWindow.pop(self)
    def goClicked(self, e=None):
        """
        The user has clicked the "ok" button. Pop self and call the callback.
        """
        self.app.appWindow.pop(self)
        if self.callback:
            self.callback()

class Spinner(QtWidgets.QLabel):
    """
    A waiting/loading spinner.
    """
    tickName = "spin"
    tickTime = 1 / 30
    def __init__(self, app, spinnerSize, width=4, pad=2):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
            spinnerSize (int): Pixel width and height of the spinner.
        """
        super().__init__()
        self.app = app
        # self.pic = pixmapFromSvg("spinner.svg", spinnerSize, spinnerSize)
        self.period = 1 # 1 rotation per second
        self.sz = spinnerSize
        self.width = width
        self.setFixedSize(spinnerSize, spinnerSize)
        self.c = spinnerSize / 2.
        # g = self.gradient = QtGui.QConicalGradient(c, c, 0)
        # g.setColorAt(0.0, QtGui.QColor("black"))
        # g.setColorAt(1.0, QtGui.QColor("white"))
        # self.qPen = QtGui.QPen(QtGui.QBrush(g), width, cap=QtCore.Qt.RoundCap)

        p = width + pad
        self.rect = (p, p, spinnerSize-2*p, spinnerSize-2*p)

        ani = self.ani = QtCore.QVariantAnimation()
        ani.setDuration(86400*1000) # give it a day
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
        return QtGui.QPen(QtGui.QBrush(g), self.width, cap=QtCore.Qt.RoundCap)
    def paintEvent(self, e):
        super().paintEvent(e)
        painter = QtGui.QPainter(self)
        painter.setRenderHints(QtGui.QPainter.HighQualityAntialiasing)
        painter.setPen(self.getPen())
        painter.drawEllipse(*self.rect)

def getTicketPrice(blockchain):
    try:
        return blockchain.stakeDiff()/1e8
    except Exception as e:
        log.error("error fetching ticket price: %s" % e)
        return False