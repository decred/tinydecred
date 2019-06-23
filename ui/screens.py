"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for detail
"""
import os
import time
from PyQt5 import QtGui, QtCore, QtWidgets
from tinydecred import keys as SK, config
from tinydecred.ui import qutilities as Q, ui
from tinydecred.wallet import Wallet
from tinydecred.util import helpers

UI_DIR = os.path.dirname(os.path.realpath(__file__))
log = helpers.getLogger("APPUI") #, logLvl=0)
cfg = config.load()

# Some commonly used ui constants.
TINY = ui.TINY
SMALL = ui.SMALL
MEDIUM = ui.MEDIUM
LARGE = ui.LARGE

# A key to identify the common screen fade in animation.
FADE_IN_ANIMATION = "fadeinanimation"

formatTraceback = helpers.formatTraceback

def pixmapFromSvg(filename, w, h, color=None):
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
    TinyDialog is a widget for handling Screen instances. This si the primary
    window of the TinyDecred application. It has a fixed (tiny!) size. 
    """
    maxWidth = 500
    maxHeight = 500
    targetPadding = 15
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__()
        self.app = app
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)

        # Set the width and height explicitly. Keep it tiny.
        screenGeo = app.qApp.primaryScreen().availableGeometry()            
        self.w = self.maxWidth if screenGeo.width() >= self.maxWidth else screenGeo.width()
        self.h =  self.maxHeight if screenGeo.height() >= self.maxHeight else screenGeo.height()
        availPadX = (screenGeo.width() - self.w) / 2
        self.padX = self.targetPadding if availPadX >= self.targetPadding else availPadX
        self.setGeometry(
            screenGeo.x() + screenGeo.width() - self.w - self.padX, 
            screenGeo.y() + screenGeo.height() - self.h, self.w, self.h)
        
        self.mainLayout = QtWidgets.QVBoxLayout(self)
        self.setFrameShape(QtWidgets.QFrame.Box)
        self.setLineWidth(1)

        # The TinyDialog is frameless, but a custom menu bar is implemented.
        menuBar, menuLayout = Q.makeWidget(QtWidgets.QWidget, "horizontal")
        self.mainLayout.addWidget(menuBar)
        menuBar.setFixedHeight(26)

        # If enabled by a Screen instance, the user can navigate directly to
        # the home screen.
        self.homeIcon = ClickyLabel(self.homeClicked)
        self.homeIcon.setPixmap(pixmapFromSvg("home.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.homeIcon, 3, 3, 3, 3))

        # If enabled by a Screen instance, the user can navigate back to the 
        # previous screen.
        self.backIcon = ClickyLabel(self.backClicked)
        self.backIcon.setPixmap(pixmapFromSvg("back.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.backIcon, 3, 3, 3, 3))

        # Separate the left and right sub-menus.
        menuLayout.addStretch(1)

        self.closeIcon = ClickyLabel(self.closeClicked)
        self.closeIcon.setPixmap(pixmapFromSvg("x.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.closeIcon, 3, 3, 3, 3))

        # Create a layout to hold Screens.
        w, self.layout = Q.makeWidget(QtWidgets.QWidget, "vertical", self)
        self.mainLayout.addWidget(w)
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
    def stack(self, w):
        """
        Add the Screen instance to the stack, making it the displayed screen.
        """
        for wgt in Q.layoutWidgets(self.layout):
            wgt.setVisible(False)
        self.layout.addWidget(w)
        w.runAnimation(FADE_IN_ANIMATION)
        w.setVisible(True)
        self.setIcons(w)
        self.setVisible(True)
    @QtCore.pyqtSlot()
    def pop(self, screen=None):
        """
        Pop the top screen from the stack. If a Screen instance is provided, 
        only pop if that is the top screen.

        Args:
            screen (Screen): optional. The the particular screen to pop.
        """
        widgetList = list(Q.layoutWidgets(self.layout))
        if len(widgetList) < 2:
            log.warning("attempted to pop an empty layout")
            return
        popped, top = widgetList[-1], widgetList[-2]
        if screen and top is not screen:
            return
        popped.setVisible(False)
        self.layout.removeWidget(popped)
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
        for wgt in list(Q.layoutWidgets(self.layout)):
            wgt.setVisible(False)
            self.layout.removeWidget(wgt)
        home.setVisible(True)
        home.runAnimation(FADE_IN_ANIMATION)
        self.layout.addWidget(home)
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

        # Update the home screen when the balance signal is received. 
        app.registerSignal(ui.BALANCE_SIGNAL, self.balanceUpdated)

        layout = self.layout
        layout.setAlignment(Q.ALIGN_LEFT)
        layout.setSpacing(50)

        # Display the current account balance.
        row, rowLyt = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        layout.addWidget(row)
        rowLyt.addStretch(1)
        self.balance = b = ClickyLabel(self.balanceClicked, "0.00")
        rowLyt.addWidget(b)
        Q.setProperties(b, fontFamily="Roboto-Bold", fontSize=45)
        self.unit = Q.makeLabel("DCR", 22, color="#777777")
        rowLyt.addWidget(self.unit, 0, Q.ALIGN_BOTTOM)
        self.unit.setContentsMargins(0, 0, 0, 5)
        rowLyt.addStretch(1)

        # Create a row to hold an address.
        col, colLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        layout.addWidget(col)
        row, rowLyt = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        colLyt.addWidget(row)
        rowLyt.addWidget(Q.makeLabel("Address", 14, color="#777777"), 0, Q.ALIGN_LEFT)
        rowLyt.addStretch(1)
        new = ClickyLabel(self.newAddressClicked, "+new")
        Q.setProperties(new, color="#777777")
        rowLyt.addWidget(new)
        self.address = Q.makeLabel("", 18, fontFamily="RobotoMono-Bold")
        colLyt.addWidget(self.address)
        self.address.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse) # | QtCore.Qt.TextSelectableByKeyboard)

        # Option buttons.
        opts, optsLyt = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        layout.addWidget(opts, 1)
        # Send DCR.
        spend = app.getButton(SMALL, "Send DCR")
        spend.setMinimumWidth(110)
        spend.clicked.connect(self.spendClicked)
        optsLyt.addWidget(spend, 0, 0, Q.ALIGN_LEFT)
        # Navigate to the settings screen.
        settings = app.getButton(SMALL, "Settings")
        settings.setMinimumWidth(110)
        settings.clicked.connect(self.settingsClicked)
        optsLyt.addWidget(settings, 0, 1, Q.ALIGN_RIGHT)
        optsLyt.setColumnStretch(0, 1)
        optsLyt.setColumnStretch(1, 1)
        optsLyt.setSpacing(35)
    def newAddressClicked(self):
        """
        Generate and display a new address. User password required.
        """
        app = self.app
        def addr(wallet):
            return app.wallet.getNewAddress()
        app.withUnlockedWallet(addr, self.setNewAddress)        
    def setNewAddress(self, address):
        """
        Callback for newAddressClicked. Sets the displayed address.
        """
        self.address.setText(address)
    def showEvent(self, e):
        """
        When this screen is shown, set the payment address.
        """
        print("-- Can I do away with this?")
        app = self.app
        if app.wallet:
            address = app.wallet.paymentAddress()
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
        log.debug("balance signal received: %f" % bal)
        dcr = bal.total*1e-8
        self.balance.setText("{0:,.2f}".format(dcr))
        self.balance.setToolTip("%.8f" % dcr)
    def spendClicked(self, e=None):
        """
        Display a form to send funds to an address. A Qt Slot, but any event 
        parameter is ignored.
        """
        self.app.appWindow.stack(self.app.sendScreen)
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
        self.pwInput = QtWidgets.QLineEdit()
        mainLayout.addWidget(self.pwInput)
        self.pwInput.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pwInput.setMinimumWidth(350)
        self.pwInput.returnPressed.connect(self.pwSubmit)
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

class PopupMessage(Screen):
    """
    A screen for displaying a simple plain test message to the users. 
    """
    def __init__(self, app):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
        """
        super().__init__(app)
        self.canGoHome = False
        self.msg = ""
        self.lbl = QtWidgets.QLabel()
        self.layout.addWidget(Q.pad(self.lbl, 0, 40, 0, 40))
    def withMessage(self, msg):
        """
        Set the current message.

        Args:
            msg (str): The message to display.

        Returns: 
            The screen itself is returned as a convenience.
        """
        self.lbl.setText(msg)
        return self

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
        app.appWindow.pop()
        if pw is None or pw == "":
            app.showMessage("you must enter a password to create a wallet")
        else:
            app.waitThread(Wallet.create, self.walletCreationComplete, app.getNetSetting(SK.currentWallet), pw, cfg.net)
    def walletCreationComplete(self, ret):
        """
        Receives the result from new wallet creation.

        Args:
            ret (None or tuple(list(str), Wallet)): The wallet and mnemonic seed
                if creation was successful. None if failed. 
        """
        app = self.app
        if ret:
            words, wallet = ret
            app.setNetSetting(SK.currentWallet, wallet.path)
            app.saveSettings()
            app.setWallet(wallet)
            app.home()
            app.showMnemonics(words)
        else:
            app.showMessage("failed to create wallet")
    def loadClicked(self):
        """
        The user has selected the "load from from" option. Prompt for a file 
        location and load the wallet.
        """
        app = self.app
        walletPath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "select wallet file")
        log.debug('loading wallet from %r' % walletPath)
        if walletPath == "":
            app.showMessage("no file selected")
        elif not os.path.isfile(walletPath):
            log.error("no file found at %s" % walletPath)
            app.showMessaage("file error. try again")
        else:
            def load(pw, userPath):
                if pw is None or pw == "":
                    self.showMessage("you must enter the password for this wallet")
                else:
                    try:
                        appWalletPath = app.getNetSetting(SK.currentWallet)
                        wallet = Wallet.openFile(userPath, pw, cfg.net)
                        # Save the wallet to the standard location.
                        wallet.path = appWalletPath
                        wallet.save()
                        app.setWallet(wallet)
                        app.home()
                    except Exception as e:
                        log.warning("exception encountered while attempting to open wallet: %s" % formatTraceback(e))
                        app.showMessage("error opening this wallet\npassword correct\ncorrect network?")
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
        return wallet.sendToAddress(round(val*1e8), addr) # raw transaction
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
        af.setFixedWidth(300)
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
            app.showMessage("sent")
        else:
            app.showMessage("transaction error")



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
        self.spinner = Spinner(self.app, 40)
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
        self.lbl = Q.makeLabel("Copy these words carefully and keep them somewhere secure. This is the only way to regenerate a lost wallet. You will not have this chance again.", 18)
        self.lbl.setWordWrap(True)
        self.layout.addWidget(self.lbl)

        # Create a label to hold the actual seed.
        lbl = QtWidgets.QLabel(" ".join(words))
        lbl.setMaximumWidth(300)
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
        self.app.appWindow.pop()

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
            app.showMessage("enter words to create a wallet")
        else:
            def create(pw, words):
                if pw:
                    app.waitThread(Wallet.createFromMnemonic, self.walletCreationComplete, words, app.getNetSetting(SK.currentWallet), pw, cfg.net)
                else:
                    app.showMessage("must enter a password to recreate the wallet")
            app.getPassword(create, words)
    def walletCreationComplete(self, wallet):
        """
        Receives the result from wallet creation.

        Args:
            ret (None or Wallet): The wallet if successfully created. None if 
                failed. 
        """
        app = self.app
        if wallet:
            app.setNetSetting(SK.currentWallet, wallet.path)
            app.saveSettings()
            app.setWallet(wallet)
            app.home()
        else:
            app.showMessage("failed to create wallet")

class Spinner(QtWidgets.QLabel):
    """
    A waiting/loading spinner.
    """
    tickName = "spin"
    tickTime = 1 / 30
    def __init__(self, app, spinnerSize):
        """
        Args:
            app (TinyDecred): The TinyDecred application instance.
            spinnerSize (int): Pixel width and height of the spinner.
        """
        super().__init__()
        self.app = app
        self.pic = pixmapFromSvg("spinner.svg", spinnerSize, spinnerSize)
        self.period = 1 # 1 rotation per second
        self.t = QtCore.QTimer()
        self.t.setInterval(Spinner.tickTime*1000)
        self.t.timeout.connect(self.tick)
    def showEvent(self, e):
        self.t.start()
    def hideEvent(self, e):
        self.t.stop()
    @QtCore.pyqtSlot()
    def tick(self):
        matrix = QtGui.QTransform()
        rotation = (time.time() % self.period) / self.period * 360
        matrix.rotate(rotation)
        self.setPixmap(self.pic.transformed(matrix, QtCore.Qt.SmoothTransformation))
        self.update()
