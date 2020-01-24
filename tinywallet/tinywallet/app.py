"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, the Decred developers
See LICENSE for details

A PyQt light wallet.
"""

import os
import sys

from PyQt5 import QtGui, QtCore, QtWidgets

from decred import config
from decred.dcr import constants as DCR
from decred.dcr.dcrdata import DcrdataBlockchain
from decred.util import helpers, database
from decred.wallet.wallet import Wallet

from tinywallet import screens, ui, qutilities as Q


# the directory of the tinywallet package
PACKAGEDIR = os.path.dirname(os.path.realpath(__file__))

# some commonly used ui constants
TINY = ui.TINY
SMALL = ui.SMALL
MEDIUM = ui.MEDIUM
LARGE = ui.LARGE

# a filename for the wallet
WALLET_FILE_NAME = "wallet.db"

formatTraceback = helpers.formatTraceback

currentWallet = "current.wallet"


class TinySignals(object):
    """
    Implements the Signals API as defined in tinydecred.api. TinySignals is used
    by the Wallet to broadcast notifications.
    """

    def __init__(self, balance=None, working=None, done=None):
        """
        Args:
            balance (func(Balance)): A function to receive balance updates.
                Updates are broadcast as an object implementing the Balance API.
        """
        dummy = lambda *a, **k: None
        self.balance = balance if balance else dummy
        self.working = working if working else dummy
        self.done = done if done else dummy


class TinyDecred(QtCore.QObject, Q.ThreadUtilities):
    """
    TinyDecred is an PyQt application for interacting with the Decred
    blockchain. TinyDecred currently implements a UI for creating and
    controlling a rudimentary, non-staking, Decred testnet light wallet.

    TinyDecred is a system tray application.
    """

    qRawSignal = QtCore.pyqtSignal(tuple)
    homeSig = QtCore.pyqtSignal()

    def __init__(self, qApp):
        """
        Args:
            qApp (QApplication): An initialized QApplication.
        """
        super().__init__()
        self.qApp = qApp
        self.cfg = config.load()
        self.log = self.init_logging()
        self.wallet = None
        # trackedCssItems are CSS-styled elements to be updated if dark mode is
        # enabled/disabled.
        self.trackedCssItems = []
        st = self.sysTray = QtWidgets.QSystemTrayIcon(QtGui.QIcon(DCR.FAVICON))
        self.contextMenu = ctxMenu = QtWidgets.QMenu()
        ctxMenu.addAction("minimize").triggered.connect(self.minimizeApp)
        ctxMenu.addAction("quit").triggered.connect(lambda *a: self.qApp.quit())
        st.setContextMenu(ctxMenu)
        st.activated.connect(self.sysTrayActivated)

        # The signalRegistry maps a signal to any number of receivers. Signals
        # are routed through a Qt Signal.
        self.signalRegistry = {}
        self.qRawSignal.connect(self.signal_)
        self.blockchainSignals = TinySignals(
            balance=self.balanceSync,
            working=lambda: self.emitSignal(ui.WORKING_SIGNAL),
            done=lambda: self.emitSignal(ui.DONE_SIGNAL),
        )

        self.loadSettings()

        dcrdataDB = database.KeyValueDatabase(
            os.path.join(self.netDirectory(), "dcr.db")
        )
        # The initialized DcrdataBlockchain will not be connected, as that is a
        # blocking operation. It will be called when the wallet is open.
        self.dcrdata = DcrdataBlockchain(
            dcrdataDB, self.cfg.net, self.getNetSetting("dcrdata"), skipConnect=True,
        )

        self.registerSignal(ui.WALLET_CONNECTED, self.syncWallet)

        # appWindow is the main application window. The TinyDialog class has
        # methods for organizing a stack of Screen widgets.
        self.appWindow = screens.TinyDialog(self)

        self.homeScreen = screens.HomeScreen(self)
        self.homeSig.connect(self.home_)
        self.home = lambda: self.homeSig.emit()

        self.appWindow.stack(self.homeScreen)

        self.pwDialog = screens.PasswordDialog(self)

        self.waitingScreen = screens.WaitingScreen(self)

        self.sendScreen = screens.SendScreen(self)

        self.confirmScreen = screens.ConfirmScreen(self)

        self.sysTray.show()
        self.appWindow.show()

        self.initialize()

    def init_logging(self):
        """
        Initialize logging for the entire app.
        """
        logDir = os.path.join(config.DATA_DIR, "logs")
        helpers.mkdir(logDir)
        logFilePath = os.path.join(logDir, "tinydecred.log")
        log = helpers.prepareLogger("APP", logFilePath, logLvl=0)
        log.info("configuration file at %s" % config.CONFIG_PATH)
        log.info("data directory at %s" % config.DATA_DIR)
        return log

    def initialize(self):
        """
        Show the initial screen based on the presence of a wallet file.
        """
        # If there is a wallet file, prompt for a password to open the wallet.
        # Otherwise, show the initialization screen.
        if os.path.isfile(self.walletFilename()):

            def login(pw):
                if pw is None or pw == "":
                    self.appWindow.showError("you must enter a password to continue")
                else:
                    path = self.walletFilename()
                    self.waitThread(self.openWallet, None, path, pw)

            self.getPassword(login)
        else:
            initScreen = screens.InitializationScreen(self)
            initScreen.setFadeIn(True)
            self.appWindow.stack(initScreen)

    def waiting(self):
        """
        Stack the waiting screen.
        """
        self.appWindow.stack(self.waitingScreen)

    def tryExecute(self, f, *a, **k):
        """
        Execute the function, catching exceptions and logging as an error. Return
        False to indicate an exception.

        Args:
            f (func): The function.
            *a (tuple): Optional positional arguments.
            **k (dict): Optional keyword arguments.

        Returns:
            value or bool: `False` on failure, the function's return value on
                success.
        """
        try:
            return f(*a, **k)
        except Exception as e:
            err_msg = "tryExecute {} failed: {}"
            self.log.error(err_msg.format(f.__name__, formatTraceback(e)))
        return False

    def waitThread(self, f, cb, *a, **k):
        """
        Wait thread shows a waiting screen while the provided function is run
        in a separate thread.

        Args:
            f (func): A function to run in a separate thread.
            cb (func): A callback to receive the return values from f.
            *args (tuple): Positional arguments passed to f.
            **kwargs (dict): Keyword arguments passed directly to f.
        """
        cb = cb if cb else lambda *a, **k: None
        self.waiting()

        def unwaiting(*cba, **cbk):
            self.appWindow.pop(self.waitingScreen)
            cb(*cba, **cbk)

        self.makeThread(self.tryExecute, unwaiting, f, *a, **k)

    def openWallet(self, path, pw):
        """
        Callback for the initial wallet load. If the load failed, probably
        because of a bad password, the provided wallet will be None.

        Args:
            wallet (Wallet): The newly opened Wallet instance.
        """
        try:
            self.dcrdata.connect()
            self.emitSignal(ui.BLOCKCHAIN_CONNECTED)
            w = Wallet.openFile(path, pw, self.blockchainSignals)
            self.setWallet(w)
            self.home()
        except Exception as e:
            self.log.warning(
                "exception encountered while attempting to open wallet: %s"
                % formatTraceback(e)
            )
            self.appWindow.showError("incorrect password")

    def getPassword(self, f, *args, **kwargs):
        """
        Calls the provided function with a user-provided password string as its
        first argument. Any additional arguments provided to getPassword are
        appended as-is to the password argument.

        Args:
            f (func): A function that will receive the user's password
                and any other provided arguments.
            *args (tuple): Positional arguments passed to f. The position
                of the args will be shifted by 1 position with the user's
                password inserted at position 0.
            **kwargs (dict): Keyword arguments passed directly to f.
        """
        self.appWindow.stack(self.pwDialog.withCallback(f, *args, **kwargs))

    def walletFilename(self):
        return self.getNetSetting(currentWallet)

    def sysTrayActivated(self, trigger):
        """
        Qt Slot called when the user interacts with the system tray icon. Shows
        the window, creating an icon in the user's application panel that
        persists until the appWindow is minimized.
        """
        if trigger == QtWidgets.QSystemTrayIcon.Trigger:
            self.appWindow.show()
            self.appWindow.activateWindow()

    def minimizeApp(self, *a):
        """
        Minimizes the application. Because TinyDecred is a system-tray app, the
        program does not halt execution, but the icon is removed from the
        application panel. Any arguments are ignored.
        """
        self.appWindow.close()
        self.appWindow.hide()

    def netDirectory(self):
        """
        The application's network directory.

        Returns:
            str: Absolute filepath of the directory for the selected network.
        """
        return os.path.join(config.DATA_DIR, self.cfg.net.Name)

    def loadSettings(self):
        """
        Load settings from the TinyConfig.
        """
        settings = self.settings = self.cfg.get("settings")
        if not settings:
            self.settings = settings = {}
            self.cfg.set("settings", self.settings)
        for k, v in (("theme", Q.LIGHT_THEME),):
            if k not in settings:
                settings[k] = v
        netSettings = self.getNetSetting()
        # if currentWallet not in netSettings:
        netSettings[currentWallet] = os.path.join(self.netDirectory(), WALLET_FILE_NAME)
        helpers.mkdir(self.netDirectory())
        self.cfg.save()

    def saveSettings(self):
        """
        Save the current settings.
        """
        self.cfg.save()

    def getSetting(self, *keys):
        """
        Get the setting using recursive keys.

        Args:
            *keys (tuple): Key strings.

        Returns:
            mixed: Value of setting for *keys.
        """
        return self.cfg.get("settings", *keys)

    def getNetSetting(self, *keys):
        """
        Get the network-specific setting using recursive keys.

        Args:
            *keys (tuple): Key strings.

        Returns:
            mixed: Value of network setting for *keys.
        """
        return self.cfg.get("networks", self.cfg.net.Name, *keys)

    def setNetSetting(self, k, v):
        """
        Set the network setting for the currently loaded network.

        Args:
            k (str): Network setting key string.
            v (value): Network setting value.
        """
        self.cfg.get("networks", self.cfg.net.Name)[k] = v

    def registerSignal(self, sig, cb, *a, **k):
        """
        Register the receiver with the signal registry.

        The callback arguments will be preceeded with any signal-specific
        arguments. For example, the BALANCE_SIGNAL will have `balance (float)`
        as its first argument, followed by unpacking *a.

        Args:
            sig (str): A notification identifier registered with the
                signalRegistry.
            cb (func): Consumer defined callback.
            *a (tuple): Positional arguments passed to cb.
            **k (dict): Keyword arguments passed directly to cb.
        """
        if sig not in self.signalRegistry:
            self.signalRegistry[sig] = []
        # Elements at indices 1 and 3 are set when emitted.
        self.signalRegistry[sig].append((cb, [], a, {}, k))

    def emitSignal(self, sig, *sigA, **sigK):
        """
        Emit a notification of type `sig`.

        Args:
            sig (str): A notification identifier registered with the
                signalRegistry.
            *sigA (tuple): Positional arguments passed to cb.
            **sigK (dict): Keyword arguments passed directly to cb.
        """
        sr = self.signalRegistry
        if sig not in sr:
            # self.log.warning("attempted to call un-registered signal %s" % sig)
            return
        for s in sr[sig]:
            sa, sk = s[1], s[3]
            sa.clear()
            sa.extend(sigA)
            sk.clear()
            sk.update(sigK)
            self.qRawSignal.emit(s)

    def signal_(self, s):
        """
        A Qt Slot used for routing signalRegistry signals.

        Args:
            s (tuple): A tuple of (func, signal args, user args, signal kwargs,
                user kwargs).
        """
        cb, sigA, a, sigK, k = s
        cb(*sigA, *a, **sigK, **k)

    def setWallet(self, wallet):
        """
        Set the current wallet.

        Args:
            wallet (Wallet): The wallet to use.
        """
        self.wallet = wallet
        self.emitSignal(ui.BALANCE_SIGNAL, wallet.balance())
        self.emitSignal(ui.WALLET_CONNECTED)

    def withUnlockedWallet(self, f, cb, *a, **k):
        """
        Run the provided function with the wallet open. This is the preferred
        method of wallet interaction, since the context is properly managed,
        i.e. the account is locked, unlocked appropriately and the mutex is
        used to ensure sequential access.

        Args:
            f (func(Wallet, ...)): A function to run with the wallet open. The
                first argument provided to f will be the open wallet.
            cb (func): A callback to receive the return value from f.
            *a (optional tuple): Additional arguments to provide to f.
            **k (optional dict): Additional keyword arguments to provide to
                f.
        """
        # step 1 receives the user password.
        def step1(pw, cb, a, k):
            if pw:
                self.waitThread(step2, cb, pw, a, k)
            else:
                self.appWindow.showError("password required to open wallet")

        # step 2 receives the open wallet.
        def step2(pw, a, k):
            self.emitSignal(ui.WORKING_SIGNAL)
            try:
                with self.wallet.open("dcr", 0, pw, self.blockchainSignals) as w:
                    r = f(w, *a, **k)
                    self.appWindow.pop(self.waitingScreen)
                    self.appWindow.pop(self.pwDialog)
                    return r
            except Exception as e:
                self.log.warning(
                    "exception encountered while performing wallet action: %s"
                    % formatTraceback(e)
                )
                self.appWindow.showError("error")
            finally:
                self.emitSignal(ui.DONE_SIGNAL)
            return False

        self.getPassword(step1, cb, a, k)

    def confirm(self, msg, cb):
        """
        Call the callback function only if the user confirms the prompt.
        """
        self.appWindow.stack(self.confirmScreen.withPurpose(msg, cb))

    def syncWallet(self):
        """
        If conditions are right, start syncing the wallet.
        """
        wallet = self.wallet
        if wallet and wallet.openAccount:
            wallet.lock()
            self.emitSignal(ui.WORKING_SIGNAL)
            self.makeThread(wallet.sync, self.doneSyncing)

    def doneSyncing(self, res):
        """
        The wallet sync is complete. Close and lock the wallet. Any arguments
        are ignored.
        """
        self.emitSignal(ui.DONE_SIGNAL)
        self.wallet.unlock()
        self.wallet.close()
        self.emitSignal(ui.SYNC_SIGNAL)

    def balanceSync(self, balance):
        """
        A Signal method for the wallet. Emits the BALANCE_SIGNAL.

        Args:
            balance (Balance): The balance to pass to subscribed receivers.
        """
        self.emitSignal(ui.BALANCE_SIGNAL, balance)

    def getButton(self, size, text, tracked=True):
        """
        Get a button of the requested size.
        Size can be one of [TINY, SMALL, MEDIUM, LARGE].
        The button is assigned a style in accordance with the current template.
        By default, the button is tracked and appropriately updated if the
        template is updated.

        Args:
            size (str): One of [TINY, SMALL, MEDIUM, LARGE].
            text (str): The text displayed on the button.
            tracked (bool): default True. Whether to track the button. If it's
                a one time use button, as for a dynamically generated dialog,
                the button should not be tracked.

        Returns:
            QPushButton: An initilized Qt pushable button.
        """
        button = QtWidgets.QPushButton(text, self.appWindow)
        button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        if self.settings["theme"] == Q.LIGHT_THEME:
            button.setProperty("button-style-class", Q.LIGHT_THEME)
        if size == TINY:
            button.setProperty("button-size-class", TINY)
        elif size == SMALL:
            button.setProperty("button-size-class", SMALL)
        elif size == MEDIUM:
            button.setProperty("button-size-class", MEDIUM)
        elif size == LARGE:
            button.setProperty("button-size-class", LARGE)
        if tracked:
            self.trackedCssItems.append(button)
        return button

    def home_(self):
        """
        Go to the home screen.
        """
        self.appWindow.setHomeScreen(self.homeScreen)

    def showMnemonics(self, words):
        """
        Show the mnemonic key. Persists until the user indicates completion.

        Args:
            list(str): List of mnemonic words.
        """
        screen = screens.MnemonicScreen(self, words)
        self.appWindow.stack(screen)


def loadFonts():
    """
    Load the application font files.
    """
    # see https://github.com/google/material-design-icons/blob/master/iconfont/codepoints
    # for conversions to unicode
    # http://zavoloklom.github.io/material-design-iconic-font/cheatsheet.html
    fontDir = os.path.join(ui.FONTDIR)
    for filename in os.listdir(fontDir):
        if filename.endswith(".ttf"):
            QtGui.QFontDatabase.addApplicationFont(os.path.join(fontDir, filename))


# Some issues' responses have indicated that certain exceptions may not be
# displayed when Qt crashes unless this excepthook redirection is used.
sys._excepthook = sys.excepthook


def exception_hook(exctype, value, tb):
    """
    Helper function to explicitly print uncaught QT exceptions.

    Args:
        exctype (Exception): The exception Class.
        value (value): The exception instance.
        tb (Traceback): The exception traceback.
    """
    print(exctype, value, tb)
    sys._excepthook(exctype, value, tb)
    sys.exit(1)


def main():
    """
    Start the TinyDecred application.
    """
    sys.excepthook = exception_hook
    QtWidgets.QApplication.setDesktopSettingsAware(False)
    roboFont = QtGui.QFont("Roboto")
    roboFont.setPixelSize(16)
    QtWidgets.QApplication.setFont(roboFont)
    qApp = QtWidgets.QApplication(sys.argv)
    qApp.setStyleSheet(Q.QUTILITY_STYLE)
    qApp.setPalette(Q.lightThemePalette)
    qApp.setWindowIcon(QtGui.QIcon(screens.pixmapFromSvg(DCR.LOGO, 64, 64)))
    qApp.setApplicationName("Tiny Decred")
    loadFonts()

    decred = TinyDecred(qApp)
    try:
        qApp.exec_()
    except Exception as e:
        print(formatTraceback(e))
    decred.sysTray.hide()
    qApp.deleteLater()
    return


if __name__ == "__main__":
    main()
