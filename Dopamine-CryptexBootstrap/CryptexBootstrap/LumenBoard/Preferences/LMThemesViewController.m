#import "LMThemesViewController.h"
#import "LMSettingsViewController.h"
#import "LMApplyViewController.h"
#import "LMConfigStore.h"
#import "LMBrandHeaderView.h"
#import "../Shared/LMThemeLibrary.h"

typedef NS_ENUM(NSInteger, LMThemeSection) {
  LMThemeSectionActive,
  LMThemeSectionInstalled,
};

// shown in the theme previews when the theme has them
static NSArray<NSString *> *LMPreviewApps(void) {
  return @[@"com.apple.mobilesafari", @"com.apple.mobilesms", @"com.apple.mobilephone", @"com.apple.camera",
           @"com.apple.mobileslideshow", @"com.apple.preferences", @"com.apple.appstore", @"com.apple.mobilemail"];
}

static UIImage *LMRenderPreview(NSArray<NSString *> *paths) {
  if (!paths.count) return nil;
  const CGFloat side = 44, gap = 3;
  UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(side, side)];
  return [renderer imageWithActions:^(UIGraphicsImageRendererContext *context) {
    NSUInteger count = MIN(paths.count, (NSUInteger)4);
    CGFloat tile = (count == 1) ? side : (side - gap) / 2;
    for (NSUInteger index = 0; index < count; index++) {
      UIImage *icon = [[UIImage imageWithContentsOfFile:paths[index]] imageByPreparingThumbnailOfSize:CGSizeMake(tile * 3, tile * 3)];
      if (!icon) continue;
      CGRect rect = (count == 1) ? CGRectMake(0, 0, side, side) : CGRectMake((index % 2) * (tile + gap), (index / 2) * (tile + gap), tile, tile);
      CGContextSaveGState(context.CGContext);
      [[UIBezierPath bezierPathWithRoundedRect:rect cornerRadius:tile * 0.225] addClip];
      [icon drawInRect:rect];
      CGContextRestoreGState(context.CGContext);
    }
  }];
}

@implementation LMThemesViewController {
  NSMutableArray<NSString *> *_active;
  NSMutableArray<NSString *> *_installed;
  NSArray<NSString *> *_visibleActive;
  NSArray<NSString *> *_visibleInstalled;
  NSMutableDictionary<NSString *, UIImage *> *_previews;
  NSDictionary<NSString *, NSDictionary *> *_details;
  UISegmentedControl *_categories;
  NSUInteger _catalogVersion;
  BOOL _scanning;
  UIButton *_applyButton;
  UISwitch *_dockBackgroundSwitch;
  LMBrandHeaderView *_brand;
}

- (UIButton *)applyButton { return _applyButton; }

- (instancetype)init {
  return [super initWithStyle:UITableViewStyleInsetGrouped];
}

- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = LMDisplayName;
  _previews = [NSMutableDictionary new];
  _details = @{};
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 76;
  self.tableView.allowsSelectionDuringEditing = YES;

  UIBarButtonItem *settingsButton = [[UIBarButtonItem alloc] initWithTitle:LMLocalized(@"Appearance") style:UIBarButtonItemStylePlain target:self action:@selector(showSettings)];
  settingsButton.accessibilityLabel = LMLocalized(@"Appearance");
  self.navigationItem.rightBarButtonItems = @[self.editButtonItem, settingsButton];

  _categories = [[UISegmentedControl alloc] initWithItems:@[LMLocalized(@"All"), LMLocalized(@"Apps"), @"CC", LMLocalized(@"Shapes"), LMLocalized(@"Other")]];
  _categories.selectedSegmentIndex = 0;
  _categories.accessibilityLabel = LMLocalized(@"Theme category: All, App icons, Control Center, Shapes and effects, Other resources");
  [_categories addTarget:self action:@selector(categoryChanged) forControlEvents:UIControlEventValueChanged];
  _brand = [LMBrandHeaderView new];
  UIView *dockControls = [self makeDockControls];
  [_categories.heightAnchor constraintGreaterThanOrEqualToConstant:44].active = YES;
  UIStackView *headerStack = [[UIStackView alloc] initWithArrangedSubviews:@[_brand, dockControls, _categories]];
  headerStack.axis = UILayoutConstraintAxisVertical;
  headerStack.spacing = 18;
  headerStack.translatesAutoresizingMaskIntoConstraints = NO;
  UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.tableView.bounds.size.width, 230)];
  [header addSubview:headerStack];
  [NSLayoutConstraint activateConstraints:@[
    [headerStack.leadingAnchor constraintEqualToAnchor:header.leadingAnchor constant:20],
    [headerStack.trailingAnchor constraintEqualToAnchor:header.trailingAnchor constant:-20],
    [headerStack.topAnchor constraintEqualToAnchor:header.topAnchor constant:12],
    [headerStack.bottomAnchor constraintEqualToAnchor:header.bottomAnchor constant:-12],
  ]];
  self.tableView.tableHeaderView = header;

  __weak typeof(self) weakSelf = self;
  UIButtonConfiguration *configuration = [UIButtonConfiguration filledButtonConfiguration];
  configuration.title = LMLocalized(@"Apply changes");
  configuration.image = [UIImage systemImageNamed:@"checkmark.circle.fill"];
  configuration.imagePadding = 8;
  configuration.cornerStyle = UIButtonConfigurationCornerStyleLarge;
  configuration.buttonSize = UIButtonConfigurationSizeLarge;
  configuration.titleAlignment = UIButtonConfigurationTitleAlignmentCenter;
  _applyButton = [UIButton buttonWithConfiguration:configuration primaryAction:[UIAction actionWithHandler:^(UIAction *action) {
    [weakSelf apply];
  }]];

  self.refreshControl = [UIRefreshControl new];
  [self.refreshControl addTarget:self action:@selector(reloadThemes) forControlEvents:UIControlEventValueChanged];
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(reloadThemes) name:UIApplicationWillEnterForegroundNotification object:nil];
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateApplyButton) name:LMConfigAppliedDidChangeNotification object:nil];
  [self reloadThemes];
}

- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];
  [self.navigationController setToolbarHidden:YES animated:animated];
  [self updateApplyButton];
}

- (void)viewDidLayoutSubviews {
  [super viewDidLayoutSubviews];
  for (UIView *part in @[self.tableView.tableHeaderView ?: [UIView new], self.tableView.tableFooterView ?: [UIView new]]) {
    if (!part.superview) continue;
    CGSize size = [part systemLayoutSizeFittingSize:CGSizeMake(self.tableView.bounds.size.width, 0) withHorizontalFittingPriority:UILayoutPriorityRequired verticalFittingPriority:UILayoutPriorityFittingSizeLevel];
    if (fabs(part.bounds.size.height - size.height) < 0.5 && part.bounds.size.width == size.width) continue;
    part.frame = CGRectMake(0, 0, size.width, size.height);
    if (part == self.tableView.tableHeaderView) self.tableView.tableHeaderView = part;
    else self.tableView.tableFooterView = part;
  }
}

#pragma mark - Data

- (void)reloadThemes {
  [LMThemeLibrary invalidate];
  NSArray *installed = [LMThemeLibrary installedThemes];
  NSMutableArray *active = [NSMutableArray new];
  for (NSString *theme in [LMConfigStore sharedStore].enabledThemes)
    if ([theme isKindOfClass:[NSString class]] && [installed containsObject:theme] && ![active containsObject:theme]) [active addObject:theme];
  _active = active;
  _installed = [installed mutableCopy];
  [_installed removeObjectsInArray:active];
  [_previews removeAllObjects];
  _details = @{};
  _scanning = YES;
  NSUInteger version = ++_catalogVersion;
  // themes that were uninstalled drop out of the configuration
  if (![active isEqualToArray:[LMConfigStore sharedStore].enabledThemes]) [self saveActiveThemes];

  [self.refreshControl endRefreshing];
  [self rebuildVisibleThemes];
  [self.tableView reloadData];
  [self updateEmptyState];
  [self updateApplyButton];
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
    NSMutableDictionary *details = [NSMutableDictionary new], *previews = [NSMutableDictionary new];
    for (NSString *theme in installed) {
      @autoreleasepool {
        NSDictionary *info = [LMThemeLibrary detailsForTheme:theme];
        details[theme] = info;
        NSDictionary *icons = [LMThemeLibrary iconsInTheme:theme];
        NSMutableArray *paths = [NSMutableArray new];
        for (NSString *bundleID in LMPreviewApps()) {
          NSString *path = icons[bundleID][LMIconLight];
          if (path && paths.count < 4) [paths addObject:path];
        }
        if (!paths.count) [paths addObjectsFromArray:info[@"PreviewPaths"]];
        UIImage *preview = LMRenderPreview(paths);
        if (preview) previews[theme] = preview;
      }
    }
    dispatch_async(dispatch_get_main_queue(), ^{
      if (version != self->_catalogVersion) return;
      self->_scanning = NO;
      self->_details = details;
      self->_previews = previews;
      [self categoryChanged];
    });
  });
}

- (void)rebuildVisibleThemes {
  const LMThemeCategories masks[] = {0, LMThemeCategoryAppIcons, LMThemeCategoryControlCenter, LMThemeCategoryIconEffects, LMThemeCategoryOther};
  NSInteger index = _categories.selectedSegmentIndex;
  LMThemeCategories mask = masks[MAX(0, MIN(index, 4))];
  NSPredicate *predicate = [NSPredicate predicateWithBlock:^BOOL(NSString *theme, NSDictionary *bindings) {
    return !mask || ([self->_details[theme][@"Categories"] unsignedIntegerValue] & mask);
  }];
  _visibleActive = [_active filteredArrayUsingPredicate:predicate];
  _visibleInstalled = [_installed filteredArrayUsingPredicate:predicate];
}

- (void)categoryChanged {
  [self rebuildVisibleThemes];
  [self.tableView reloadData];
  [self updateEmptyState];
  [self updateApplyButton];
}

- (NSString *)themeAtIndexPath:(NSIndexPath *)indexPath {
  NSArray *themes = (indexPath.section == LMThemeSectionActive) ? _visibleActive : _visibleInstalled;
  return (indexPath.row < (NSInteger)themes.count) ? themes[indexPath.row] : nil;
}

- (BOOL)saveActiveThemes {
  [LMConfigStore sharedStore].enabledThemes = _active;
  NSError *error;
  if ([[LMConfigStore sharedStore] save:&error]) {
    [self updateApplyButton];
    return YES;
  }
  UIAlertController *alert = [UIAlertController alertControllerWithTitle:LMLocalized(@"Couldn't save") message:error.localizedDescription preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:LMLocalized(@"OK") style:UIAlertActionStyleCancel handler:nil]];
  [self presentViewController:alert animated:YES completion:nil];
  return NO;
}

#pragma mark - UI state

- (UIView *)makeDockControls {
  UILabel *title = [UILabel new];
  title.text = LMLocalized(@"Hide dock background only");
  title.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
  title.adjustsFontForContentSizeCategory = YES;
  title.numberOfLines = 0;
  UILabel *detail = [UILabel new];
  detail.text = LMLocalized(@"Dock icons stay visible");
  detail.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
  detail.adjustsFontForContentSizeCategory = YES;
  detail.textColor = [UIColor secondaryLabelColor];
  detail.numberOfLines = 0;
  UIStackView *labels = [[UIStackView alloc] initWithArrangedSubviews:@[title, detail]];
  labels.axis = UILayoutConstraintAxisVertical;
  labels.spacing = 4;
  _dockBackgroundSwitch = [UISwitch new];
  _dockBackgroundSwitch.onTintColor = [UIColor systemRedColor];
  _dockBackgroundSwitch.accessibilityLabel = title.text;
  _dockBackgroundSwitch.accessibilityHint = detail.text;
  [_dockBackgroundSwitch setContentCompressionResistancePriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
  [_dockBackgroundSwitch addTarget:self action:@selector(dockBackgroundChanged:) forControlEvents:UIControlEventValueChanged];
  UIStackView *toggleRow = [[UIStackView alloc] initWithArrangedSubviews:@[labels, _dockBackgroundSwitch]];
  toggleRow.alignment = UIStackViewAlignmentCenter;
  toggleRow.spacing = 12;
  __weak typeof(self) weakSelf = self;
  UIButtonConfiguration *configuration = [UIButtonConfiguration tintedButtonConfiguration];
  configuration.title = LMLocalized(@"Apply dock only");
  configuration.image = [UIImage systemImageNamed:@"rectangle.bottomthird.inset.filled"];
  configuration.imagePadding = 8;
  configuration.buttonSize = UIButtonConfigurationSizeMedium;
  configuration.cornerStyle = UIButtonConfigurationCornerStyleLarge;
  UIButton *apply = [UIButton buttonWithConfiguration:configuration primaryAction:[UIAction actionWithHandler:^(UIAction *action) {
    [weakSelf applyDockOnly];
  }]];
  apply.accessibilityHint = LMLocalized(@"Update the background · No respring");
  UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[toggleRow, apply]];
  stack.axis = UILayoutConstraintAxisVertical;
  stack.spacing = 12;
  stack.translatesAutoresizingMaskIntoConstraints = NO;
  UIView *card = [UIView new];
  card.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
  card.layer.cornerRadius = 16;
  [card addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[
    [stack.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
    [stack.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
    [stack.topAnchor constraintEqualToAnchor:card.topAnchor constant:16],
    [stack.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-16],
    [apply.heightAnchor constraintGreaterThanOrEqualToConstant:44],
  ]];
  return card;
}

- (void)updateEmptyState {
  if (_visibleActive.count + _visibleInstalled.count) {
    self.tableView.tableFooterView = nil;
    return;
  }
  UIImageView *image = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"square.grid.2x2" withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:48 weight:UIImageSymbolWeightLight]]];
  image.tintColor = [UIColor tertiaryLabelColor];
  UILabel *title = [UILabel new];
  BOOL installed = _active.count + _installed.count > 0;
  title.text = _scanning && installed ? LMLocalized(@"Scanning themes…") : (installed ? LMLocalized(@"No themes in this category") : LMLocalized(@"No themes installed"));
  title.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle3];
  title.adjustsFontForContentSizeCategory = YES;
  title.numberOfLines = 0;
  title.textAlignment = NSTextAlignmentCenter;
  UILabel *detail = [UILabel new];
  detail.text = installed ? LMLocalized(@"Choose All to see every installed pack, or pull down to refresh.") : LMLocalized(@"Install a theme from your package manager, then pull down to refresh. Home Screen options work without a theme.");
  detail.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
  detail.adjustsFontForContentSizeCategory = YES;
  detail.textColor = [UIColor secondaryLabelColor];
  detail.numberOfLines = 0;
  detail.textAlignment = NSTextAlignmentCenter;
  UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[image, title, detail]];
  stack.axis = UILayoutConstraintAxisVertical;
  stack.alignment = UIStackViewAlignmentCenter;
  stack.spacing = 10;
  stack.translatesAutoresizingMaskIntoConstraints = NO;
  UIView *background = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.tableView.bounds.size.width, 240)];
  [background addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[
    [stack.topAnchor constraintEqualToAnchor:background.topAnchor constant:30],
    [stack.bottomAnchor constraintEqualToAnchor:background.bottomAnchor constant:-30],
    [stack.leadingAnchor constraintEqualToAnchor:background.leadingAnchor constant:32],
    [stack.trailingAnchor constraintEqualToAnchor:background.trailingAnchor constant:-32],
    [title.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
    [detail.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
  ]];
  self.tableView.tableFooterView = background;
  [self.view setNeedsLayout];
}

- (void)updateApplyButton {
  UIButtonConfiguration *configuration = _applyButton.configuration;
  LMConfigStore *store = [LMConfigStore sharedStore];
  _dockBackgroundSwitch.on = store.hideDockBackground;
  configuration.subtitle = store.hasUnappliedChanges ? LMLocalized(@"Changes not applied yet") : (store.appliedSkippedCount ? [NSString localizedStringWithFormat:LMLocalized(@"Applied with %lu skipped items"), (unsigned long)store.appliedSkippedCount] : nil);
  _applyButton.configuration = configuration;
  self.editButtonItem.enabled = _active.count > 1;
  _brand.subtitleLabel.text = _scanning ? LMLocalized(@"Scanning themes…") : [NSString localizedStringWithFormat:LMLocalized(@"%lu active · %lu installed"), (unsigned long)_active.count, (unsigned long)(_active.count + _installed.count)];
  [self.view setNeedsLayout];
}

- (void)setEditing:(BOOL)editing animated:(BOOL)animated {
  [super setEditing:editing animated:animated];
  [self.tableView setEditing:editing animated:animated];
}

#pragma mark - Actions

- (void)dockBackgroundChanged:(UISwitch *)toggle {
  LMConfigStore *store = [LMConfigStore sharedStore];
  BOOL previous = store.hideDockBackground;
  store.hideDockBackground = toggle.on;
  NSError *error = nil;
  if (![store save:&error]) {
    store.hideDockBackground = previous;
    toggle.on = previous;
    [self showSaveError:error];
  }
  [self updateApplyButton];
}

- (void)showSaveError:(NSError *)error {
  UIAlertController *alert = [UIAlertController alertControllerWithTitle:LMLocalized(@"Couldn't save") message:error.localizedDescription preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:LMLocalized(@"OK") style:UIAlertActionStyleCancel handler:nil]];
  [self presentViewController:alert animated:YES completion:nil];
}

- (void)applyDockOnly {
  NSError *error = nil;
  if (![[LMConfigStore sharedStore] save:&error]) { [self showSaveError:error]; return; }
  [self presentViewController:[[LMApplyViewController alloc] initWithApplyingDockOnly] animated:YES completion:nil];
}

- (void)showSettings {
  [self.navigationController pushViewController:[LMSettingsViewController new] animated:YES];
}

- (void)apply {
  if (![self saveActiveThemes]) return;
  [self presentViewController:[[LMApplyViewController alloc] initWithClearingIconCache:NO] animated:YES completion:^{
    [self updateApplyButton];
  }];
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  return (_active.count + _installed.count) ? 2 : 0;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
  return (section == LMThemeSectionActive) ? _visibleActive.count : _visibleInstalled.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
  return (section == LMThemeSectionActive) ? LMLocalized(@"Active") : LMLocalized(@"Installed");
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
  if (section == LMThemeSectionActive)
    return _visibleActive.count ? LMLocalized(@"App icons, CC icons, and shape layers can be enabled together. For each resource, the theme higher up wins. Tap Edit to change the order.") : LMLocalized(@"Tap a supported theme below to activate it.");
  return _categories.selectedSegmentIndex == 4 ? LMLocalized(@"Respring animations, badges, dock artwork, and other resource packs are not supported yet.") : nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
  UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"Theme"] ? : [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"Theme"];
  NSString *theme = [self themeAtIndexPath:indexPath];
  NSDictionary *info = _details[theme];
  NSMutableArray *labels = [NSMutableArray new];
  if ([info[@"AppIconCount"] unsignedIntegerValue]) [labels addObject:[NSString localizedStringWithFormat:LMLocalized(@"Apps: %lu icons"), (unsigned long)[info[@"AppIconCount"] unsignedIntegerValue]]];
  if ([info[@"CCAssetCount"] unsignedIntegerValue]) [labels addObject:[NSString localizedStringWithFormat:LMLocalized(@"CC: %lu glyphs"), (unsigned long)[info[@"CCAssetCount"] unsignedIntegerValue]]];
  if ([info[@"EffectCount"] unsignedIntegerValue]) [labels addObject:[NSString localizedStringWithFormat:LMLocalized(@"Shapes/effects: %lu layers"), (unsigned long)[info[@"EffectCount"] unsignedIntegerValue]]];
  if (info && !labels.count) [labels addObject:LMLocalized(@"Other resources · Not supported yet")];

  UIListContentConfiguration *content = [UIListContentConfiguration subtitleCellConfiguration];
  content.text = [LMThemeLibrary displayNameForTheme:theme];
  content.textProperties.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
  content.textProperties.numberOfLines = 2;
  content.secondaryText = info ? [labels componentsJoinedByString:@" · "] : LMLocalized(@"Scanning artwork…");
  content.secondaryTextProperties.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
  content.secondaryTextProperties.numberOfLines = 0;
  content.secondaryTextProperties.color = [UIColor secondaryLabelColor];
  content.image = _previews[theme] ? : [UIImage systemImageNamed:@"square.grid.2x2"];
  content.imageProperties.maximumSize = CGSizeMake(44, 44);
  content.imageProperties.reservedLayoutSize = CGSizeMake(44, 44);
  content.imageProperties.tintColor = [UIColor tertiaryLabelColor];
  cell.contentConfiguration = content;
  cell.accessoryType = (indexPath.section == LMThemeSectionActive) ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
  cell.showsReorderControl = YES;
  cell.accessibilityTraits = UIAccessibilityTraitButton | (indexPath.section == LMThemeSectionActive ? UIAccessibilityTraitSelected : 0);
  return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
  [tableView deselectRowAtIndexPath:indexPath animated:YES];
  NSString *theme = [self themeAtIndexPath:indexPath];
  if (!theme) return;
  if (indexPath.section == LMThemeSectionActive) {
    [_active removeObject:theme];
    NSUInteger position = [_installed indexOfObject:theme inSortedRange:NSMakeRange(0, _installed.count) options:NSBinarySearchingInsertionIndex usingComparator:^NSComparisonResult(NSString *a, NSString *b) {
      return [[LMThemeLibrary displayNameForTheme:a] localizedCaseInsensitiveCompare:[LMThemeLibrary displayNameForTheme:b]];
    }];
    [_installed insertObject:theme atIndex:position];
  } else {
    NSDictionary *info = _details[theme] ?: [LMThemeLibrary detailsForTheme:theme];
    if ([info[@"Categories"] unsignedIntegerValue] == LMThemeCategoryOther) {
      UIAlertController *alert = [UIAlertController alertControllerWithTitle:LMLocalized(@"Unsupported resource pack") message:LMLocalized(@"This pack contains respring animations, badges, or dock artwork. Rebug supports app icons, Control Center PNGs, and icon masks and effects.") preferredStyle:UIAlertControllerStyleAlert];
      [alert addAction:[UIAlertAction actionWithTitle:LMLocalized(@"OK") style:UIAlertActionStyleCancel handler:nil]];
      [self presentViewController:alert animated:YES completion:nil];
      return;
    }
    [_installed removeObject:theme];
    [_active addObject:theme];
  }
  [self categoryChanged];
  [self saveActiveThemes];
}

- (BOOL)tableView:(UITableView *)tableView canMoveRowAtIndexPath:(NSIndexPath *)indexPath {
  return indexPath.section == LMThemeSectionActive;
}

- (NSIndexPath *)tableView:(UITableView *)tableView targetIndexPathForMoveFromRowAtIndexPath:(NSIndexPath *)source toProposedIndexPath:(NSIndexPath *)proposed {
  if (proposed.section == LMThemeSectionActive) return proposed;
  return [NSIndexPath indexPathForRow:(_visibleActive.count ? _visibleActive.count - 1 : 0) inSection:LMThemeSectionActive];
}

- (void)tableView:(UITableView *)tableView moveRowAtIndexPath:(NSIndexPath *)source toIndexPath:(NSIndexPath *)destination {
  NSMutableArray *reordered = [_visibleActive mutableCopy];
  NSString *theme = reordered[source.row];
  [reordered removeObjectAtIndex:source.row];
  [reordered insertObject:theme atIndex:destination.row];
  // Preserve the positions of themes hidden by the category filter.
  NSSet *visible = [NSSet setWithArray:_visibleActive];
  NSUInteger cursor = 0;
  for (NSUInteger index = 0; index < _active.count; index++) if ([visible containsObject:_active[index]]) _active[index] = reordered[cursor++];
  _visibleActive = reordered;
  [self saveActiveThemes];
}

- (UITableViewCellEditingStyle)tableView:(UITableView *)tableView editingStyleForRowAtIndexPath:(NSIndexPath *)indexPath {
  return UITableViewCellEditingStyleNone;
}

- (BOOL)tableView:(UITableView *)tableView shouldIndentWhileEditingRowAtIndexPath:(NSIndexPath *)indexPath {
  return NO;
}

@end
