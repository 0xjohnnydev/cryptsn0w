include $(THEOS)/makefiles/common.mk

# Foundation only: providers for the upstream renderer and local UI rendering.
TWEAK_NAME = LumenBoardCore
LumenBoardCore_FILES = LMIconStore.m LMIconArtwork.m LMIconServices.x
LumenBoardCore_CFLAGS = -fobjc-arc -Wall -Wno-deprecated-declarations
LumenBoardCore_FRAMEWORKS = Foundation CoreGraphics ImageIO

include $(THEOS_MAKE_PATH)/tweak.mk
