from tinydecred import keys as SK, config
from tinydecred.ui import qutilities as Q, ui
from tinydecred.wallet import Wallet
from PyQt5 import QtGui, QtCore, QtWidgets
from tinydecred.pydecred import helpers
import os
import time
import traceback

log = helpers.getLogger("APPUI") #, logLvl=0)
cfg = config.load()

TINY = ui.TINY
SMALL = ui.SMALL
MEDIUM = ui.MEDIUM
LARGE = ui.LARGE

FADE_IN_ANIMATION = "fadeinanimation"
UI_DIR = os.path.dirname(os.path.realpath(__file__))

def pixmapFromSvg(filename, w, h, color=None):
    return QtGui.QIcon(os.path.join(UI_DIR, "icons", filename)).pixmap(w, h)

class TinyDialog(QtWidgets.QFrame):
    maxWidth = 450
    maxHeight = 550
    targetPadding = 20
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        screenGeo = app.application.primaryScreen().availableGeometry()
        self.w = self.maxWidth if screenGeo.width() >= self.maxWidth else screenGeo.width()
        self.h =  self.maxHeight if screenGeo.height() >= self.maxHeight else screenGeo.height()
        availPadX = (screenGeo.width() - self.w) / 2
        self.padX = self.targetPadding if availPadX >= self.targetPadding else availPadX
        self.setGeometry(screenGeo.width() - self.w - self.padX, screenGeo.height() - self.h, self.w, self.h)
        self.mainLayout = QtWidgets.QVBoxLayout(self)
        self.setFrameShape(QtWidgets.QFrame.Box)
        self.setLineWidth(1)

        menuBar, menuLayout = Q.makeWidget(QtWidgets.QWidget, "horizontal")
        self.mainLayout.addWidget(menuBar)
        menuBar.setFixedHeight(26)

        self.homeIcon = ClickyLabel(self.homeClicked)
        self.homeIcon.setPixmap(pixmapFromSvg("home.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.homeIcon, 3, 3, 3, 3))

        self.backIcon = ClickyLabel(self.backClicked)
        self.backIcon.setPixmap(pixmapFromSvg("back.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.backIcon, 3, 3, 3, 3))

        menuLayout.addStretch(1)

        self.closeIcon = ClickyLabel(self.closeClicked)
        self.closeIcon.setPixmap(pixmapFromSvg("x.svg", 20, 20))
        menuLayout.addWidget(Q.pad(self.closeIcon, 3, 3, 3, 3))

        w, self.layout = Q.makeWidget(QtWidgets.QWidget, "vertical", self)
        self.mainLayout.addWidget(w)
    def closeEvent(self, e):
        self.hide()
        e.ignore()
    def stack(self, w):
        for wgt in Q.layoutWidgets(self.layout):
            wgt.setVisible(False)
        self.layout.addWidget(w)
        w.runAnimation(FADE_IN_ANIMATION)
        w.setVisible(True)
        self.setIcons(w)
        self.setVisible(True)
    def pop(self):
        widgetList = list(Q.layoutWidgets(self.layout))
        if len(widgetList) < 2:
            log.warning("attempted to pop an empty layout")
            return
        popped, top = widgetList[-1], widgetList[-2]
        popped.setVisible(False)
        self.layout.removeWidget(popped)
        top.setVisible(True)
        top.runAnimation(FADE_IN_ANIMATION)
        self.setIcons(top)
        self.setIcons(top)
        widgetList = list(Q.layoutWidgets(self.layout))
    def setHomeScreen(self, home):
        for wgt in list(Q.layoutWidgets(self.layout)):
            wgt.setVisible(False)
            self.layout.removeWidget(wgt)
        home.setVisible(True)
        home.runAnimation(FADE_IN_ANIMATION)
        self.layout.addWidget(home)
        self.setIcons(home)
    def setIcons(self, top):
        self.backIcon.setVisible(top.isPoppable)
        self.homeIcon.setVisible(top.canGoHome)
    def homeClicked(self):
        while self.layout.count() > 1:
            self.pop()
    def closeClicked(self):
        self.hide()
    def backClicked(self):
        self.pop()

class Screen(QtWidgets.QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.isPoppable = False
        self.canGoHome = True
        self.animations = {}
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
        if ani in self.animations:
            return self.animations[ani].start()
    def setFadeIn(self, v):
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
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.isPoppable = False
        self.canGoHome = False
        app.registerSignal(ui.BALANCE_SIGNAL, self.balanceUpdated)

        layout = self.layout
        layout.setAlignment(Q.ALIGN_LEFT)
        layout.setSpacing(60)

        # Balance
        row, rowLyt = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        layout.addWidget(row)
        rowLyt.addStretch(1)
        self.balance = b = ClickyLabel(self.balanceClicked, "0.00")
        rowLyt.addWidget(b)
        font = QtGui.QFont("Roboto-Heavy")
        font.setPixelSize(55)
        b.setFont(font)
        self.unit = Q.makeLabel("DCR", 22, color="#777777")
        rowLyt.addWidget(self.unit, 0, Q.ALIGN_BOTTOM)
        rowLyt.addStretch(1)

        # Create a row to hold an address.
        col, colLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        layout.addWidget(col)
        row, rowLyt = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        colLyt.addWidget(row)
        rowLyt.addWidget(Q.makeLabel("Address", 14, color="#777777"), 0, Q.ALIGN_LEFT)
        rowLyt.addStretch(1)
        new = ClickyLabel(self.newAddressClicked, "+new")
        Q.setLabelColor(new, "#777777")

        # Options
        opts, optsLyt = Q.makeWidget(QtWidgets.QWidget, Q.GRID)
        layout.addWidget(opts, 1)
        spend = app.getButton(SMALL, "Send DCR")
        spend.setMinimumWidth(110)
        spend.clicked.connect(self.spendClicked)
        optsLyt.addWidget(spend, 0, 0, Q.ALIGN_LEFT)
        settings = app.getButton(SMALL, "Settings")
        settings.setMinimumWidth(110)
        settings.clicked.connect(self.settingsClicked)
        optsLyt.addWidget(settings, 0, 1, Q.ALIGN_RIGHT)
        optsLyt.setColumnStretch(0, 1)
        optsLyt.setColumnStretch(1, 1)
        optsLyt.setSpacing(40)

        rowLyt.addWidget(new)
        self.address = Q.makeLabel("", 16)
        colLyt.addWidget(self.address)
        self.address.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse) # | QtCore.Qt.TextSelectableByKeyboard)
    def newAddressClicked(self):
        app = self.app
        wallet = app.wallet
        if wallet.isOpen():
            self.getNewAddress(wallet)
        else:
            def pwcb(pw): # password callback
                if not pw or pw == "":
                    app.showMessage("incorrect password")
                else:
                    try:
                        wallet.open(pw)
                        self.getNewAddress(wallet)
                    except Exception:
                        app.showMessage("failed to open wallet with that password")
            app.getPassword(pwcb)
    def getNewAddress(self, wallet):
        address = wallet.openAccount.getNextPaymentAddress()
        self.address.setText(address)
    def showEvent(self, e):
        app = self.app
        if app.wallet:
            address = app.wallet.openAccount.paymentAddress()
            self.address.setText(address)
    def balanceClicked(self):
        log.info("--balance clicked")
    def balanceUpdated(self, bal):
        print("--balance signal received")
        self.balance.setText(helpers.formatNumber(bal*1e-8))
    def spendClicked(self, e):
        self.app.appWindow.stack(self.app.sendScreen)
    def settingsClicked(self, e):
        print("--settings clicked")

class PasswordDialog(Screen):
    def __init__(self, app):
        super().__init__(app)
        content, mainLayout = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.layout.addWidget(Q.pad(content, 20, 20, 20, 20))
        mainLayout.setSpacing(10)
        self.isPoppable = True
        self.canGoHome = False

        self.label = QtWidgets.QLabel("password")
        mainLayout.addWidget(self.label)
        self.pwInput = QtWidgets.QLineEdit()
        mainLayout.addWidget(self.pwInput)
        self.pwInput.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pwInput.returnPressed.connect(self.pwSubmit)
        self.callback = lambda p: None

        row, lyt = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        mainLayout.addWidget(row)
        toggle = Q.QToggle(self, callback=self.showPwToggled)
        lyt.addWidget(QtWidgets.QLabel("show password"))
        lyt.addWidget(toggle)
    def showEvent(self, e):
        self.pwInput.setFocus()
    def showPwToggled(self, state, switch):
        if state: 
            self.pwInput.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.pwInput.setEchoMode(QtWidgets.QLineEdit.Password)
    def pwSubmit(self):
        self.callback(self.pwInput.text())
    def withCallback(self, callback, *args, **kwargs):
        self.callback = lambda p, a=args, k=kwargs: callback(p, *a, **k)
        return self

class ClickyLabel(QtWidgets.QLabel):
    def __init__(self, callback, *a):
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
        if self.mouseDown == False:
            return
        qSize = self.size()
        ePos = e.pos()
        x, y = ePos.x(), ePos.y()
        if x < 0 or y < 0 or x > qSize.width() or y > qSize.height():
            self.mouseDown = False

class PopupMessage(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.canGoHome = False
        self.msg = ""
        self.lbl = QtWidgets.QLabel()
        self.layout.addWidget(Q.pad(self.lbl, 0, 40, 0, 40))
    def withMessage(self, msg):
        self.lbl.setText(msg)
        return self

class InitializationScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.canGoHome = False
        self.layout.setSpacing(20)
        lbl = Q.makeLabel("Welcome!", 26, font="Roboto-Medium")
        self.layout.addWidget(lbl)
        self.layout.addWidget(Q.makeLabel("How would you like to begin?", 16))

        self.initBttn = app.getButton(SMALL, "create wallet")
        self.layout.addWidget(self.initBttn)
        self.initBttn.clicked.connect(self.initClicked)

        self.loadBttn = app.getButton(SMALL, "load wallet")
        self.layout.addWidget(self.loadBttn)
        self.loadBttn.clicked.connect(self.loadClicked)

        self.restoreBttn = app.getButton(SMALL, "restore from seed")
        self.layout.addWidget(self.restoreBttn)
        self.restoreBttn.clicked.connect(self.restoreClicked)
    def initClicked(self):
        self.app.getPassword(self.initPasswordCallback)
    def initPasswordCallback(self, pw):
        # either way, pop the password window
        app = self.app
        app.appWindow.pop()
        if pw is None or pw == "":
            app.showMessage("you must enter a password to create a wallet")
        else:
            app.waitThread(Wallet.create, self.walletCreationComplete, app.getNetSetting(SK.currentWallet), pw, cfg.net)
    def walletCreationComplete(self, ret):
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
        app = self.app
        walletPath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "select wallet file")
        print('walletPath: %r' % walletPath)
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
                        wallet = Wallet.open(userPath, pw, cfg.net)
                        wallet.path = appWalletPath
                        wallet.save()
                        app.setWallet(wallet)
                        app.home()
                    except Exception as e:
                        log.warning("exception encountered while attempting to open wallet: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
                        app.showMessage("error opening this wallet\npassword correct\ncorrect network?")
            app.getPassword(load, walletPath)
    def restoreClicked(self):
        restoreScreen = MnemonicRestorer(self.app)
        self.app.appWindow.stack(restoreScreen)

class SendScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.canGoHome = True
        self.isPoppable = True
        layout = self.layout
        layout.setSpacing(25)

        layout.addWidget(Q.makeLabel("Sending Decred", 25, fontFamily="Roboto-Medium"))

        # collect the value to send
        col, colLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        layout.addWidget(col)
        colLyt.addWidget(Q.makeLabel("how much?", 16, color="#777777"), 0, Q.ALIGN_LEFT)
        self.valField = vf = QtWidgets.QLineEdit()
        self.valField.setFixedWidth(175)
        colLyt.addWidget(vf, 0, Q.ALIGN_LEFT)

        col, colLyt = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        layout.addWidget(col)
        colLyt.addWidget(Q.makeLabel("to address", 16, color="#777777"), 0, Q.ALIGN_LEFT)
        self.addressField = af = QtWidgets.QLineEdit()
        af.setFixedWidth(300)
        colLyt.addWidget(af)

        send = app.getButton(SMALL, "send")
        layout.addWidget(send, 0, Q.ALIGN_RIGHT)
        send.setFixedWidth(125)
        send.clicked.connect(self.sendClicked)
    def sendClicked(self, e):
        val = float(self.valField.text())
        address = self.addressField.text()
        log.debug("sending %f to %s" % (val, address))
        self.app.withUnlockedWallet(self.sendWithWallet, val, address)
    def sendWithWallet(self, wallet, val, addr):
        log.debug("wallet unlocked for send")
        app = self.app
        def send(val, addr):
            try:
                tx = wallet.createRawSpend(int(val*1e8), addr) # raw transaction
                for dcrdata in app.dcrdatas:
                    print("--sending %r to dcrdata" % tx.hex().encode("ascii"))
                    dcrdata.insight.api.tx.send.post({
                        "rawtx": tx.hex(),
                    })
            except Exception as e:
                log.error("failed to send: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
        app.waitThread(send, self.sent, val, addr)
    def sent(self, res):
        print("--send res: %s" % repr(res))



class WaitingScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.isPoppable = False
        self.canGoHome = False
        self.spinner = Spinner(self.app)
        self.layout.addWidget(self.spinner)

class MnemonicScreen(Screen):
    def __init__(self, app, words):
        super().__init__(app)
        self.isPoppable = True
        self.canGoHome = True
        self.wgt.setMaximumWidth(320)
        self.layout.setSpacing(10)
        self.lbl = Q.makeLabel("Copy these words carefully and keep them somewhere secure. This is the only way to regenerate a lost wallet. You will not have this chance again.", 18)
        self.lbl.setWordWrap(True)
        self.layout.addWidget(self.lbl)
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
        button = app.getButton(SMALL, "all done", tracked=False) # the mnemonic screen is not persistent. Don't track this button.
        self.layout.addWidget(button)
        button.clicked.connect(self.clearAndClose)
    def clearAndClose(self, e):
        self.lbl.setText("")
        self.app.appWindow.pop()

class MnemonicRestorer(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.isPoppable = True
        self.canGoHome = False
        self.wgt.setMaximumWidth(320)
        self.layout.setSpacing(10)
        self.lbl = Q.makeLabel("Enter your mnemonic seed here. Separate words with whitespace.", 18)
        self.lbl.setWordWrap(True)
        self.layout.addWidget(self.lbl)
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
        button = app.getButton(SMALL, "OK", tracked=False) # the mnemonic screen is not persistent. Don't track this button.
        self.layout.addWidget(button)
        button.clicked.connect(self.tryWords)
    def showEvent(self, e):
        self.edit.setFocus()
    def tryWords(self, e):
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
        app = self.app
        if wallet:
            app.setNetSetting(SK.currentWallet, wallet.path)
            app.saveSettings()
            app.setWallet(wallet)
            app.home()
        else:
            app.showMessage("failed to create wallet")

class Spinner(QtWidgets.QLabel):
    tickName = "spin"
    tickTime = 1 / 30
    spinnerSize = 40
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.pic = pixmapFromSvg("spinner.svg", Spinner.spinnerSize, Spinner.spinnerSize)
        self.period = 1 # 1 rotation per second
    def showEvent(self, e):
        self.app.scheduleFunction(Spinner.tickName, self.tick, time.time()+Spinner.tickTime, repeatEvery=Spinner.tickTime)
    def hideEvent(self, e):
        self.app.cancelFunction(Spinner.tickName)
    def tick(self):
        matrix = QtGui.QTransform()
        rotation = (time.time() % self.period) / self.period * 360
        matrix.rotate(rotation)
        self.setPixmap(self.pic.transformed(matrix, QtCore.Qt.SmoothTransformation))
        self.update()
