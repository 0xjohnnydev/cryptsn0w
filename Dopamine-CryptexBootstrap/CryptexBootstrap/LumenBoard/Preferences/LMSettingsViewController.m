#import "LMSettingsViewController.h"
#import "LMApplyViewController.h"
#import "LMConfigStore.h"

typedef NS_ENUM(NSInteger, LMSettingsSection) {
  LMSettingsSectionHomeScreen,
  LMSettingsSectionIconStyle,
  LMSettingsSectionApply,
  LMSettingsSectionIconCache,
  LMSettingsSectionAbout,
  LMSettingsSectionCount,
};

@implementation LMSettingsViewController
- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = LMLocalized(@"Appearance");
  self.view.tintColor = [UIColor systemRedColor];
  self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 76;
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refreshAppliedState) name:LMConfigAppliedDidChangeNotification object:nil];
}

- (void)refreshAppliedState {
  [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:LMSettingsSectionApply] withRowAnimation:UITableViewRowAnimationNone];
}

- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];
  [self.navigationController setToolbarHidden:YES animated:animated];
  [self.tableView reloadData];
}

- (UISwitch *)switchWithValue:(BOOL)value action:(SEL)action {
  UISwitch *toggle = [UISwitch new];
  toggle.on = value;
  toggle.onTintColor = [UIColor systemRedColor];
  [toggle addTarget:self action:action forControlEvents:UIControlEventValueChanged];
  return toggle;
}

- (BOOL)save {
  NSError *error = nil;
  if ([[LMConfigStore sharedStore] save:&error]) {
    [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:LMSettingsSectionApply] withRowAnimation:UITableViewRowAnimationNone];
    return YES;
  }
  UIAlertController *alert = [UIAlertController alertControllerWithTitle:LMLocalized(@"Couldn't save") message:error.localizedDescription preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:LMLocalized(@"OK") style:UIAlertActionStyleCancel handler:nil]];
  [self presentViewController:alert animated:YES completion:nil];
  return NO;
}

- (void)systemShapeChanged:(UISwitch *)toggle { [LMConfigStore sharedStore].useSystemIconShape = toggle.on; [self save]; }
- (void)keepAppearanceChanged:(UISwitch *)toggle { [LMConfigStore sharedStore].keepIconsInDarkAndTinted = toggle.on; [self save]; }
- (void)dockBackgroundChanged:(UISwitch *)toggle { [LMConfigStore sharedStore].hideDockBackground = toggle.on; [self save]; }
- (void)iconLabelsChanged:(UISwitch *)toggle { [LMConfigStore sharedStore].hideIconLabels = toggle.on; [self save]; }

- (void)confirmClearIconCache {
  UIAlertController *alert = [UIAlertController alertControllerWithTitle:LMLocalized(@"Clear icon cache?") message:LMLocalized(@"All app icons are rendered again, then SpringBoard restarts. This can take a minute.") preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:LMLocalized(@"Cancel") style:UIAlertActionStyleCancel handler:nil]];
  [alert addAction:[UIAlertAction actionWithTitle:LMLocalized(@"Clear & Respring") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
    if ([self save]) [self presentViewController:[[LMApplyViewController alloc] initWithClearingIconCache:YES] animated:YES completion:nil];
  }]];
  [self presentViewController:alert animated:YES completion:nil];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return LMSettingsSectionCount; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
  switch (section) {
    case LMSettingsSectionHomeScreen: case LMSettingsSectionIconStyle: case LMSettingsSectionApply: case LMSettingsSectionAbout: return 2;
    case LMSettingsSectionIconCache: return 1;
  }
  return 0;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
  switch (section) {
    case LMSettingsSectionHomeScreen: return LMLocalized(@"Home Screen");
    case LMSettingsSectionIconStyle: return LMLocalized(@"Theme icons");
    case LMSettingsSectionApply: return LMLocalized(@"Apply");
    case LMSettingsSectionIconCache: return LMLocalized(@"Maintenance");
    case LMSettingsSectionAbout: return LMDisplayName;
  }
  return nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
  switch (section) {
    case LMSettingsSectionHomeScreen: return LMLocalized(@"Apply changes to update labels and themes. Use Apply dock only to update just the background immediately.");
    case LMSettingsSectionIconStyle: return LMLocalized(@"Turn off iOS icon shape to use a mask from a Shapes pack. Backgrounds and overlays work with theme or stock icons.");
    case LMSettingsSectionApply: return [LMConfigStore sharedStore].hasUnappliedChanges ? LMLocalized(@"You have changes waiting to be applied.") : LMLocalized(@"Your saved changes are applied.");
    case LMSettingsSectionIconCache: return LMLocalized(@"Use this if artwork still looks wrong after installing or updating a theme.");
    case LMSettingsSectionAbout: return LMLocalized(@"Built on LumenBoard by xsxs18-dev. Existing themes and selections are preserved.");
  }
  return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
  UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
  UIListContentConfiguration *content = [UIListContentConfiguration subtitleCellConfiguration];
  LMConfigStore *config = [LMConfigStore sharedStore];
  cell.selectionStyle = UITableViewCellSelectionStyleNone;
  NSString *symbol;
  if (indexPath.section == LMSettingsSectionHomeScreen && indexPath.row == 0) {
    content.text = LMLocalized(@"Hide icon labels");
    content.secondaryText = LMLocalized(@"App and folder names · Works with Small icons");
    symbol = @"textformat";
    cell.accessoryView = [self switchWithValue:config.hideIconLabels action:@selector(iconLabelsChanged:)];
  } else if (indexPath.section == LMSettingsSectionHomeScreen) {
    content.text = LMLocalized(@"Hide dock background only");
    content.secondaryText = LMLocalized(@"Dock icons stay visible");
    symbol = @"rectangle.bottomthird.inset.filled";
    cell.accessoryView = [self switchWithValue:config.hideDockBackground action:@selector(dockBackgroundChanged:)];
  } else if (indexPath.section == LMSettingsSectionIconStyle && indexPath.row == 0) {
    content.text = LMLocalized(@"iOS icon shape");
    content.secondaryText = LMLocalized(@"Use the standard icon mask");
    symbol = @"app";
    cell.accessoryView = [self switchWithValue:config.useSystemIconShape action:@selector(systemShapeChanged:)];
  } else if (indexPath.section == LMSettingsSectionIconStyle) {
    content.text = LMLocalized(@"Keep in dark & tinted mode");
    content.secondaryText = LMLocalized(@"Keep themed artwork across appearances");
    symbol = @"circle.lefthalf.filled";
    cell.accessoryView = [self switchWithValue:config.keepIconsInDarkAndTinted action:@selector(keepAppearanceChanged:)];
  } else if (indexPath.section == LMSettingsSectionApply) {
    content.text = indexPath.row == 0 ? LMLocalized(@"Apply changes & respring") : LMLocalized(@"Apply dock only");
    content.secondaryText = indexPath.row == 0 ? LMLocalized(@"Themes, icon labels, and dock appearance") : LMLocalized(@"Update the background · No respring");
    content.textProperties.color = self.view.tintColor;
    symbol = indexPath.row == 0 ? @"checkmark.circle.fill" : @"rectangle.bottomthird.inset.filled";
    cell.selectionStyle = UITableViewCellSelectionStyleDefault;
  } else if (indexPath.section == LMSettingsSectionIconCache) {
    content.text = LMLocalized(@"Clear icon cache & respring");
    content.textProperties.color = self.view.tintColor;
    symbol = @"arrow.clockwise";
    cell.selectionStyle = UITableViewCellSelectionStyleDefault;
  } else if (indexPath.row == 0) {
    content = [UIListContentConfiguration valueCellConfiguration];
    content.text = LMLocalized(@"Version");
    content.secondaryText = LMBundle().infoDictionary[@"CFBundleShortVersionString"];
    symbol = @"info.circle";
  } else {
    content.text = LMLocalized(@"Theme library");
    content.secondaryText = LMThemesDirectoryDisplayName;
    symbol = @"folder";
  }
  content.textProperties.numberOfLines = 0;
  content.secondaryTextProperties.numberOfLines = 0;
  content.secondaryTextProperties.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
  content.secondaryTextProperties.color = [UIColor secondaryLabelColor];
  content.image = [UIImage systemImageNamed:symbol];
  content.imageProperties.tintColor = self.view.tintColor;
  content.imageProperties.reservedLayoutSize = CGSizeMake(28, 28);
  cell.contentConfiguration = content;
  return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
  [tableView deselectRowAtIndexPath:indexPath animated:YES];
  if (indexPath.section == LMSettingsSectionIconCache) { [self confirmClearIconCache]; return; }
  if (indexPath.section != LMSettingsSectionApply || ![self save]) return;
  LMApplyViewController *apply = indexPath.row == 1 ? [[LMApplyViewController alloc] initWithApplyingDockOnly] : [[LMApplyViewController alloc] initWithClearingIconCache:NO];
  [self presentViewController:apply animated:YES completion:nil];
}
@end
