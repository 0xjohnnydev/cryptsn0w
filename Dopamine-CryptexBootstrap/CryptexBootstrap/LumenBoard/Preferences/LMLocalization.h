#pragma once

#import <UIKit/UIKit.h>

NSBundle *LMBundle(void);
#define LMDisplayName @"☆ Rebug"

#define LMLocalized(text) [LMBundle() localizedStringForKey:(text) value:(text) table:nil]
