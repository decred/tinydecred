from pydecred import helpers
from pydecred import constants as C
from pydecred.dcrdata import DcrDataClient
import pydecred.mainnet as mainnet
import pydecred.testnet as testnet
from tinydecred import config
from tinydecred import wallet
from tinydecred import crypto
import qutilities as Q
from PyQt5 import QtGui, QtCore, QtWidgets
import os
import sys
import traceback
import time

PASSWORD_TIMEOUT = 300 * 1000 # milliseconds
PACKAGEDIR =  os.path.dirname(os.path.realpath(__file__))

WALLET_FILE_NAME = "wallet.db"
_walletDir = os.path.join(config.DATA_DIR, "wallets")
helpers.mkdir(_walletDir)
DEFAULT_WALLET_PATH = os.path.join(_walletDir, WALLET_FILE_NAME)

BLACK = QtGui.QColor("black")

TINY = "tiny"
SMALL = "small"
MEDIUM = "medium"
LARGE = "large"

def pixmapFromSvg(filename, w, h, color=None):
    return QtGui.QIcon(os.path.join(PACKAGEDIR, "icons", filename)).pixmap(w, h)

class TinyDecred(QtCore.QObject, Q.ThreadUtilities):
    def __init__(self, application):
        super().__init__()
        self.application = application
        self.password = None
        self.passwordTimer = Q.makeTimer(self.losePassword)
        self.trackedCssItems = []

        self.wallet = wallet.Wallet()

       	self.sysTray = QtWidgets.QSystemTrayIcon(QtGui.QIcon(C.FAVICON))
        ctxMenu = self.contextMenu = QtWidgets.QMenu()
        ctxMenu.addAction("quit").triggered.connect(lambda *a: self.application.quit())
        ctxMenu.addAction("minimize").triggered.connect(self.minimizeApp)
       	self.sysTray.setContextMenu(ctxMenu)
        self.appWindow = TinyDialog(self)

        self.homeScreen = HomeScreen(self)
        self.appWindow.layout.addWidget(self.homeScreen)

        self.pwDialog = PasswordDialog(self)
        self.sysTray.activated.connect(self.sysTrayActivated)

        self.message = PopupMessage(self)

       	self.sysTray.show()
        self.appWindow.show()

        self.loadSettings()

        if not os.path.isfile(self.getSetting("current.wallet")):
            initScreen = InitializationScreen(self)
            self.appWindow.stack(initScreen)

    def resetPwTimer(self):
        self.passwordTimer.start(PASSWORD_TIMEOUT)
    def getPassword(self, callback, *args, **kwargs):
        if self.password is not None:
            self.resetPwTimer()
            return self.password
        self.appWindow.stack(self.pwDialog.withCallback(callback, *args, **kwargs))
    def losePassword(self):
        self.password = None
    def sysTrayActivated(self, trigger):
        if trigger == QtWidgets.QSystemTrayIcon.Trigger:
            self.appWindow.show()
            self.appWindow.activateWindow()
    def minimizeApp(self, *a):
        self.appWindow.close()
        self.appWindow.hide()
    def loadSettings(self):
        self.settings = cfg.get("settings")
        if not self.settings:
            self.settings = {}
            self.settings["theme"] = Q.LIGHT_THEME
            self.settings["wallet"] = {}
            self.settings["current.wallet"] = DEFAULT_WALLET_PATH
            cfg.set("settings", self.settings)
            cfg.save()
    def saveSettings(self):
        cfg.save()
    def getSetting(self, *keys):
        return cfg.get("settings", *keys)
    def showMessage(self, msg):
        self.appWindow.stack(self.message.withMessage(msg))
        self.scheduleFunction("unshow.message", self.appWindow.pop, time.time()+5)
    def initialLogin(self, pw):
        if pw is None:
            self.showMessaage("You must create a password to use TinyDecred")
    def getButton(self, size, text, tracked=True):
        """
        Get a button of the requested size. 
        Size can be one of [TINY, SMALL,MEDIUM, LARGE].
        The button is assigned a style in accordance with the current template.
        By default, the button is tracked and appropriately updated if the template is updated.

        :param str size: One of [TINY, SMALL,MEDIUM, LARGE]
        :param str text: The text displayed on the button
        :param bool tracked: default True. Whether to track the button. If its a one time use button, i.e. for a dynamically generated dialog, the button should not be tracked.
        """
        button = QtWidgets.QPushButton(text, self.appWindow)
        button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        if self.settings["theme"] == Q.LIGHT_THEME:
            button.setProperty("button-style-class", Q.LIGHT_THEME)
        if size == TINY:
            button.setProperty("button-size-class", TINY)
        elif size == SMALL:
            button.setProperty("button-size-class", SMALL)
        elif size ==MEDIUM:
            button.setProperty("button-size-class",MEDIUM)
        elif size == LARGE:
            button.setProperty("button-size-class", LARGE)
        if tracked:
            self.trackedCssItems.append(button)
        return button


class TinyDialog(QtWidgets.QFrame):
    maxWidth = 450
    maxHeight = 650
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
        self.setIcons(top)
        widgetList = list(Q.layoutWidgets(self.layout))
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
        vLayout = QtWidgets.QVBoxLayout(self)
        vLayout.addStretch(1)
        hw, hLayout = Q.makeWidget(QtWidgets.QWidget, Q.HORIZONTAL)
        vLayout.addWidget(hw)
        hLayout.addStretch(1)
        w, self.layout = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        hLayout.addWidget(w)
        hLayout.addStretch(1)
        vLayout.addStretch(1)

class HomeScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.layout.addWidget(Q.pad(Q.makeLabel("this is the homescreen", 16), 0, 40, 0, 40))

class PasswordDialog(Screen):
    def __init__(self, app):
        super().__init__(app)
        content, mainLayout = Q.makeWidget(QtWidgets.QWidget, Q.VERTICAL)
        self.layout.addWidget(Q.pad(content, 20, 20, 20, 20))
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
        self.layout.setSpacing(5)
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
            app.wallet.create(app.getSetting("current.wallet"), pw)
            app.wallet.close()
            app.settings["current.wallet"] = app.wallet.path
            app.saveSettings()
            app.appWindow.pop() # pop itself
    def loadClicked(self):
        walletpath,  = QtWidgets.QFileDialog.getOpenFileName(self, "select wallet file")
        if walletpath == "":
            pass
    def restoreClicked(self):
        print("restoring")


def loadFonts():
    # see https://github.com/google/material-design-icons/blob/master/iconfont/codepoints
    # for conversions to unicode
    # http://zavoloklom.github.io/material-design-iconic-font/cheatsheet.html
    fontDir = os.path.join(C.FONTDIR)
    for filename in os.listdir(fontDir):
        if filename.endswith(".ttf"):
            QtGui.QFontDatabase.addApplicationFont(os.path.join(fontDir, filename))

def runTinyDecred():
    QtWidgets.QApplication.setDesktopSettingsAware(False)
    roboFont = QtGui.QFont("Roboto")
    roboFont.setPixelSize(16)
    QtWidgets.QApplication.setFont(roboFont);
    qApp = QtWidgets.QApplication(sys.argv)
    qApp.setStyleSheet(Q.QUTILITY_STYLE)
    qApp.setPalette(Q.lightThemePalette)
    loadFonts()

    decred = TinyDecred(qApp)
    try:
        qApp.exec_()
    except Exception as e:
        try:
            log.warning("Error encountered: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
        except Exception:
            pass
        finally:
            print("Error encountered: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
    decred.sysTray.hide()
    qApp.deleteLater()
    return


if __name__ == '__main__':
    cfg = config.load()
    logDir = os.path.join(config.DATA_DIR, "logs")
    helpers.mkdir(logDir)
    log = helpers.prepareLogger("WLLT", os.path.join(logDir, "tinydecred.log"))

    # runTinyDecred()

    seed = crypto.generateSeed()
    hdSeed = crypto.newMaster(seed, testnet)
    helpers.dumpJSON(hdSeed)