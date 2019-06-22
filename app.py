from tinydecred import keys as SK, config
from tinydecred.pydecred import helpers, constants as C
from tinydecred.pydecred.dcrdata import DcrDataClient
from tinydecred.wallet import Wallet
from tinydecred.ui import screens, ui, qutilities as Q
from tinydecred.pydecred.database import KeyValueDatabase
from PyQt5 import QtGui, QtCore, QtWidgets
import os
import sys
import traceback
import time

PASSWORD_TIMEOUT = 300 * 1000 # milliseconds
PACKAGEDIR = os.path.dirname(os.path.realpath(__file__))

TINY = ui.TINY
SMALL = ui.SMALL
MEDIUM = ui.MEDIUM
LARGE = ui.LARGE

WALLET_FILE_NAME = "wallet.db"

def tryExecute(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        log.error("tryExecute %s failed: %s \n %s" % (f.__name__, repr(e), traceback.print_tb(e.__traceback__)))
    return False

class TinyDecred(QtCore.QObject, Q.ThreadUtilities):
    qRawSignal = QtCore.pyqtSignal(tuple)
    def __init__(self, application):
        super().__init__()
        self.application = application
        self.dbManager = KeyValueDatabase(os.path.join(self.netDirectory(), "tiny.db"))
        self.password = None
        self.passwordTimer = Q.makeTimer(self.losePassword)
        self.wallet = None
        self.trackedCssItems = []
       	self.sysTray = QtWidgets.QSystemTrayIcon(QtGui.QIcon(C.FAVICON))
        ctxMenu = self.contextMenu = QtWidgets.QMenu()
        ctxMenu.addAction("minimize").triggered.connect(self.minimizeApp)
        ctxMenu.addAction("quit").triggered.connect(lambda *a: self.application.quit())
       	self.sysTray.setContextMenu(ctxMenu)
        self.dcrdatas = {}
        self.signalRegistry = {}
        self.qRawSignal.connect(self.signal_)
        self.loadSettings()

        self.appWindow = screens.TinyDialog(self)

        self.homeScreen = screens.HomeScreen(self)
        self.appWindow.stack(self.homeScreen)

        self.pwDialog = screens.PasswordDialog(self)
        self.sysTray.activated.connect(self.sysTrayActivated)

        self.message = screens.PopupMessage(self)

        self.waitingScreen = screens.WaitingScreen(self)

        self.sendScreen = screens.SendScreen(self)

        self.sysTray.show()
        self.appWindow.show()

        if not os.path.isfile(self.getNetSetting(SK.currentWallet)):
            initScreen = screens.InitializationScreen(self)
            initScreen.setFadeIn(True)
            self.appWindow.stack(initScreen)
        else:
            def openw(path, pw, net):
                try:
                    wallet = Wallet.openFile(path, pw, cfg.net)
                    wallet.lock()
                    return wallet
                except Exception as e:
                    log.warning("exception encountered while attempting to open wallet: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
                    self.showMessage("incorrect password")
            def login(pw):
                if pw is None or pw == "":
                    self.showMessage("you must enter a password to continue")
                else:
                    path = self.getNetSetting(SK.currentWallet)
                    self.waitThread(openw, self.finishOpen, path, pw, cfg.net)                    
            self.getPassword(login)
        self.makeThread(self.initDcrdata, self.finishDcrdata, self.getNetSetting("dcrdatas"))
    def finishOpen(self, wallet):
        if wallet == None:
            return
        self.setWallet(wallet)
        self.home()
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
    def netDirectory(self):
        return os.path.join(config.DATA_DIR, cfg.net.Name)
    def loadSettings(self):
        settings = self.settings = cfg.get("settings")
        if not settings:
            self.settings = settings = {}
            cfg.set("settings", self.settings)
        # initialize dict settings
        # for k in ():
        #     if k not in settings:
        #         settings[k] = {}
        # initialize key-value settings
        for k, v in (("theme", Q.LIGHT_THEME), ):
            if k not in settings:
                settings[k] = v
        netSettings = self.getNetSetting()
        # if SK.currentWallet not in netSettings:
        netSettings[SK.currentWallet] = os.path.join(self.netDirectory(), WALLET_FILE_NAME)
        helpers.mkdir(self.netDirectory())
        cfg.save()
    def saveSettings(self):
        cfg.save()
    def getSetting(self, *keys):
        return cfg.get("settings", *keys)
    def getNetSetting(self, *keys):
        return cfg.get("networks", cfg.net.Name, *keys)
    def setNetSetting(self, k, v):
        cfg.get("networks", cfg.net.Name)[k] = v
    def registerSignal(self, sig, cb, *a, **k):
        """
        The callback arguments will be preceeded with any signal-specific arguments.
        For example, the BALANCE_SIGNAL will have `balance (float)` as its first argument.
        """
        if sig not in self.signalRegistry:
            self.signalRegistry[sig] = []
        # elements at indices 1 and 3 are set when emitted
        self.signalRegistry[sig].append((cb, [], a, {},  k))
    def emitSignal(self, sig, *sigA, **sigK):
        """
        emitSignal routes through a Qt signal.
        """
        sr = self.signalRegistry
        if sig not in sr:
            # log.warning("attempted to call un-registered signal %s" % sig)
            return
        for s in sr[sig]:
            sa, sk = s[1], s[3]
            sa.clear()
            sa.extend(sigA)
            sk.clear()
            sk.update(sigK)
            self.qRawSignal.emit(s)
    def signal_(self, s):
        cb, sigA, a,  sigK, k = s
        cb(*sigA, *a, **sigK, **k)
    def setWallet(self, wallet):
        wallet.setChain(cfg.net)
        self.wallet = wallet
        self.emitSignal(ui.BALANCE_SIGNAL, wallet.balance())
        self.tryInitSync()
    def withUnlockedWallet(self, f, cb, *a, **k):
        def step1(pw, cb, a, k):
            if pw:
                self.waitThread(step2, cb, pw, a, k)
            else:
                self.showMessage("password required to open wallet")
        def step2(pw, a, k):
            try:
                with self.wallet.open(pw.encode("utf-8")) as w:
                    print("--running %s with open wallet" % f.__name__)
                    r = f(w, *a, **k)
                    print("--finished %s" % f.__name__)
                    return r
            except Exception as e:
                log.warning("exception encountered while performing wallet action: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
                self.showMessage("error")
            return False
        self.getPassword(step1, cb, a, k)
    def broadcast(self, txHex):
        print("--send2")
        try:
            for dcrdata in self.dcrdatas:
                print("--sending %r to dcrdata" % txHex)
                dcrdata.insight.api.tx.send.post({
                    "rawtx": txHex,
                })
                return True
        except Exception as e:
            log.error("broadcast error: %s" % e)
        return False
    def tryInitSync(self):
        wallet = self.wallet
        if wallet and wallet.openAccount and self.dcrdatas:
            self.makeThread(wallet.sync, self.doneSyncing, self.dcrdatas, self.dbManager, self.balanceSync)
    def doneSyncing(self, res):
        self.wallet.unlock()
        self.wallet.close()
        self.emitSignal(ui.SYNC_SIGNAL)
    @QtCore.pyqtSlot(str)
    def balanceSync(self, balance):
        self.wallet.save()
        self.home()
        self.emitSignal(ui.BALANCE_SIGNAL, balance)
    def initDcrdata(self, uris):
        dcrdatas = []
        for uri in uris:
            try:
                dcrdatas.append(DcrDataClient(uri, customPaths=(
                    "/tx/send",
                    "/insight/api/addr/{address}/utxo",
                    "insight/api/tx/send"
                )))
                log.debug("dcrdata client connected to %s" % uri)
            except Exception:
                log.error("unable to initialize dcrdata connection at %s" % uri)
        return dcrdatas
    def finishDcrdata(self, dcrdatas):
        self.dcrdatas = dcrdatas
        self.tryInitSync()
    @QtCore.pyqtSlot(str)
    def showMessage(self, msg):
        self.appWindow.stack(self.message.withMessage(msg))
        self.scheduleFunction("unshow.message", self.appWindow.pop, time.time()+5)
    def initialLogin(self, pw):
        if pw is None:
            self.showMessage("You must create a password to use TinyDecred")
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
    @QtCore.pyqtSlot()
    def home(self):
        self.appWindow.setHomeScreen(self.homeScreen)
    def waiting(self):
        self.appWindow.stack(self.waitingScreen)
    def waitThread(self, f, cb, *a, **k):
        self.waiting()
        def unwaiting(*cba, **cbk):
            self.appWindow.pop(self.waitingScreen)
            cb(*cba, **cbk)
        self.makeThread(tryExecute, unwaiting, f, *a, **k)
    def showMnemonics(self, words):
        screen = screens.MnemonicScreen(self, words)
        self.appWindow.stack(screen)

def loadFonts():
    # see https://github.com/google/material-design-icons/blob/master/iconfont/codepoints
    # for conversions to unicode
    # http://zavoloklom.github.io/material-design-iconic-font/cheatsheet.html
    fontDir = os.path.join(C.FONTDIR)
    for filename in os.listdir(fontDir):
        if filename.endswith(".ttf"):
            QtGui.QFontDatabase.addApplicationFont(os.path.join(fontDir, filename))

sys._excepthook = sys.excepthook 
def exception_hook(exctype, value, traceback):
    print(exctype, value, traceback)
    sys._excepthook(exctype, value, traceback) 
    sys.exit(1) 

def runTinyDecred():
    sys.excepthook = exception_hook
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
        print("Error encountered: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))            
    finally: 
        decred.cleanUp()
    decred.sysTray.hide()
    qApp.deleteLater()
    return


if __name__ == '__main__':
    cfg = config.load()
    logDir = os.path.join(config.DATA_DIR, "logs")
    helpers.mkdir(logDir)
    log = helpers.prepareLogger("APP", os.path.join(logDir, "tinydecred.log"), logLvl=0)

    runTinyDecred()

