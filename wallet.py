from pydecred import helpers
from pydecred import constants as C
from pydecred.dcrdata import DcrDataClient
from tinydecred import config
import qutilities as Q
from PyQt5 import QtGui, QtCore, QtWidgets
import os
import sys
import traceback

class TinyWallet(QtCore.QObject, Q.ThreadUtilities):
    def __init__(self, application):
        super().__init__()
        self.application = application
       	ctxMenu = self.contextMenu = QtWidgets.QMenu()
       	ctxMenu.addAction("test").triggered.connect(lambda *a: print("blue"))
       	ctxMenu.addAction("quit").triggered.connect(lambda *a: self.application.quit())
       	self.sysTray = QtWidgets.QSystemTrayIcon(QtGui.QIcon(C.FAVICON))
       	self.sysTray.setContextMenu(ctxMenu)
       	self.sysTray.show()



def loadFonts():
        # see https://github.com/google/material-design-icons/blob/master/iconfont/codepoints
        # for conversions to unicode
        # http://zavoloklom.github.io/material-design-iconic-font/cheatsheet.html
        fontDir = os.path.join(C.FONTDIR)
        for filename in os.listdir(fontDir):
            if filename.endswith(".ttf"):
                QtGui.QFontDatabase.addApplicationFont(os.path.join(fontDir, filename))

def runTinyWallet():
    QtWidgets.QApplication.setDesktopSettingsAware(False)
    QtWidgets.QApplication.setFont(QtGui.QFont("Roboto"));
    app = QtWidgets.QApplication(sys.argv)
    loadFonts()

    wallet = TinyWallet(app)

    app.setStyleSheet(Q.QUTILITY_STYLE)
    try:
        app.exec_()
    except Exception as e:
        try:
            log.warning("Error encountered: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
        except Exception:
            pass
        finally:
            print("Error encountered: %s \n %s" % (repr(e), traceback.print_tb(e.__traceback__)))
    app.deleteLater()
    return


if __name__ == '__main__':
	cfg = config.load()
	logDir = os.path.join(config.DATA_DIR, "logs")
	helpers.mkdir(logDir)
	log = helpers.prepareLogger("WLLT", os.path.join(logDir, "wallet.log"))
	runTinyWallet()