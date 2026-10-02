include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = LumenBoardPrefs
LumenBoardPrefs_FILES = LMRootViewController.m LMLocalization.m LMConfigStore.m LMThemesViewController.m LMSettingsViewController.m LMApplyViewController.m LMBrandHeaderView.m ../Shared/LMThemeLibrary.m ../Shared/LMHomeScreenOptions.m
LumenBoardPrefs_FRAMEWORKS = UIKit QuartzCore
LumenBoardPrefs_PRIVATE_FRAMEWORKS = Preferences
LumenBoardPrefs_CFLAGS = -fobjc-arc -Wall -Wno-deprecated-declarations -Wno-unguarded-availability-new
LumenBoardPrefs_LDFLAGS = -F$(CURDIR)/Frameworks
LumenBoardPrefs_INSTALL_PATH = /Library/PreferenceBundles
LumenBoardPrefs_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/bundle.mk
