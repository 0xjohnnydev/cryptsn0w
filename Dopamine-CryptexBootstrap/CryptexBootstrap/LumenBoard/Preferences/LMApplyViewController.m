#import "LMApplyViewController.h"
#import "LMConfigStore.h"
#import <notify.h>

@implementation LMApplyViewController {
  BOOL _clearIconCache;
  BOOL _dockOnly;
  BOOL _springBoardAnswered;
  BOOL _finished;
  int _progressToken;
  UIImageView *_symbol;
  UILabel *_titleLabel;
  UILabel *_statusLabel;
  UIProgressView *_progressView;
  UIButton *_closeButton;
  UIButton *_continueButton;
  NSString *_partialGeneration;
  NSUInteger _requestSequence;
}

- (instancetype)initWithClearingIconCache:(BOOL)clearIconCache {
  if ((self = [super initWithNibName:nil bundle:nil])) {
    _clearIconCache = clearIconCache;
    _progressToken = NOTIFY_TOKEN_INVALID;
    self.modalPresentationStyle = UIModalPresentationPageSheet;
    self.modalInPresentation = YES;
    UISheetPresentationController *sheet = self.sheetPresentationController;
    sheet.detents = @[[UISheetPresentationControllerDetent mediumDetent], [UISheetPresentationControllerDetent largeDetent]];
    sheet.preferredCornerRadius = 28;
  }
  return self;
}

- (void)dealloc {
  if (_progressToken != NOTIFY_TOKEN_INVALID) notify_cancel(_progressToken);
}

- (instancetype)initWithApplyingDockOnly {
  if ((self = [self initWithClearingIconCache:NO])) _dockOnly = YES;
  return self;
}

- (void)viewDidLoad {
  [super viewDidLoad];
  self.view.backgroundColor = [UIColor systemBackgroundColor];
  self.view.tintColor = [UIColor systemRedColor];

  _symbol = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"arrow.triangle.2.circlepath" withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:52 weight:UIImageSymbolWeightMedium]]];
  _symbol.tintColor = self.view.tintColor;

  _titleLabel = [UILabel new];
  _titleLabel.font = [[UIFontMetrics metricsForTextStyle:UIFontTextStyleTitle2] scaledFontForFont:[UIFont systemFontOfSize:24 weight:UIFontWeightSemibold]];
  _titleLabel.adjustsFontForContentSizeCategory = YES;
  _titleLabel.numberOfLines = 2;
  _titleLabel.textAlignment = NSTextAlignmentCenter;
  _titleLabel.text = _dockOnly ? LMLocalized(@"Updating dock") : (_clearIconCache ? LMLocalized(@"Rebuilding icons") : LMLocalized(@"Applying changes"));

  _progressView = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
  _progressView.translatesAutoresizingMaskIntoConstraints = NO;

  _statusLabel = [UILabel new];
  _statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
  _statusLabel.adjustsFontForContentSizeCategory = YES;
  _statusLabel.textColor = [UIColor secondaryLabelColor];
  _statusLabel.textAlignment = NSTextAlignmentCenter;
  _statusLabel.numberOfLines = 0;
  _statusLabel.text = LMLocalized(@"Preparing…");

  UIButtonConfiguration *configuration = [UIButtonConfiguration grayButtonConfiguration];
  configuration.title = LMLocalized(@"Close");
  configuration.cornerStyle = UIButtonConfigurationCornerStyleCapsule;
  configuration.buttonSize = UIButtonConfigurationSizeLarge;
  __weak typeof(self) weakSelf = self;
  _closeButton = [UIButton buttonWithConfiguration:configuration primaryAction:[UIAction actionWithHandler:^(UIAction *action) {
    [weakSelf dismissViewControllerAnimated:YES completion:nil];
  }]];
  _closeButton.hidden = YES;

  UIButtonConfiguration *continueConfiguration = [UIButtonConfiguration filledButtonConfiguration];
  continueConfiguration.title = LMLocalized(@"Continue applying");
  continueConfiguration.cornerStyle = UIButtonConfigurationCornerStyleCapsule;
  continueConfiguration.buttonSize = UIButtonConfigurationSizeLarge;
  _continueButton = [UIButton buttonWithConfiguration:continueConfiguration primaryAction:[UIAction actionWithHandler:^(UIAction *action) {
    [weakSelf continueApplying];
  }]];
  _continueButton.hidden = YES;

  UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[_symbol, _titleLabel, _progressView, _statusLabel, _continueButton, _closeButton]];
  stack.axis = UILayoutConstraintAxisVertical;
  stack.alignment = UIStackViewAlignmentCenter;
  stack.spacing = 16;
  [stack setCustomSpacing:24 afterView:_symbol];
  stack.translatesAutoresizingMaskIntoConstraints = NO;
  UIScrollView *scroll = [UIScrollView new];
  scroll.translatesAutoresizingMaskIntoConstraints = NO;
  UIView *content = [UIView new];
  content.translatesAutoresizingMaskIntoConstraints = NO;
  [self.view addSubview:scroll];
  [scroll addSubview:content];
  [content addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[
    [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
    [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    [scroll.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
    [scroll.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor],
    [content.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor],
    [content.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor],
    [content.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor],
    [content.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor],
    [content.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor],
    [content.heightAnchor constraintGreaterThanOrEqualToAnchor:scroll.frameLayoutGuide.heightAnchor],
    [stack.centerYAnchor constraintEqualToAnchor:content.centerYAnchor],
    [stack.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:24],
    [stack.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-24],
    [stack.topAnchor constraintGreaterThanOrEqualToAnchor:content.topAnchor constant:24],
    [stack.bottomAnchor constraintLessThanOrEqualToAnchor:content.bottomAnchor constant:-24],
    [_titleLabel.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
    [_statusLabel.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
    [_progressView.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
  ]];
  if (UIContentSizeCategoryIsAccessibilityCategory(self.traitCollection.preferredContentSizeCategory)) self.sheetPresentationController.selectedDetentIdentifier = UISheetPresentationControllerDetentIdentifierLarge;
}

- (void)viewDidAppear:(BOOL)animated {
  [super viewDidAppear:animated];
  if (_progressToken != NOTIFY_TOKEN_INVALID) return;

  // Only the completion state acknowledges a successful render and map write.
  __weak typeof(self) weakSelf = self;
  uint32_t status = notify_register_dispatch(LMNotifyProgress, &_progressToken, dispatch_get_main_queue(), ^(int token) {
    uint64_t state = 0;
    notify_get_state(token, &state);
    [weakSelf showProgress:(uint32_t)(state >> 32) of:(uint32_t)(state & 0xFFFFFFFF)];
  });
  if (status != NOTIFY_STATUS_OK) {
    [self showFailure:LMLocalized(@"Couldn't request the update. Close this sheet and try again.")];
    return;
  }
  [self beginWaiting];
  if (notify_post(_dockOnly ? LMNotifyApplyDock : (_clearIconCache ? LMNotifyClearCache : LMNotifyApply)) != NOTIFY_STATUS_OK) [self showFailure:LMLocalized(@"Couldn't request the update. Close this sheet and try again.")];
}

- (void)beginWaiting {
  _finished = NO;
  _springBoardAnswered = NO;
  _closeButton.hidden = YES;
  _continueButton.hidden = YES;
  _progressView.hidden = NO;
  _progressView.progress = 0;
  _titleLabel.text = _dockOnly ? LMLocalized(@"Updating dock") : (_clearIconCache ? LMLocalized(@"Rebuilding icons") : LMLocalized(@"Applying changes"));
  _statusLabel.text = LMLocalized(@"Preparing…");
  _symbol.image = [UIImage systemImageNamed:@"arrow.triangle.2.circlepath" withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:52 weight:UIImageSymbolWeightMedium]];
  _symbol.tintColor = self.view.tintColor;
  self.modalInPresentation = YES;
  CABasicAnimation *spin = [CABasicAnimation animationWithKeyPath:@"transform.rotation.z"];
  spin.toValue = @(M_PI * 2);
  spin.duration = 3;
  spin.repeatCount = HUGE_VALF;
  [_symbol.layer addAnimation:spin forKey:@"spin"];
  NSUInteger sequence = ++_requestSequence;
  __weak typeof(self) weakSelf = self;
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (strongSelf && sequence == strongSelf->_requestSequence) [strongSelf showFailureIfSpringBoardIsSilent];
  });
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(90 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (strongSelf && sequence == strongSelf->_requestSequence && !strongSelf->_finished) [strongSelf showFailure:LMLocalized(@"The update timed out. Close this sheet and try again.")];
  });
}

- (void)continueApplying {
  if (!_partialGeneration.length) return;
  NSError *error = nil;
  NSData *request = [NSPropertyListSerialization dataWithPropertyList:@{@"Generation": _partialGeneration} format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
  if (!request || ![request writeToFile:LMContinueRequestPath options:NSDataWritingAtomic error:&error]) {
    _statusLabel.text = LMLocalized(@"Couldn't save the continuation request. Close this sheet and try Apply again.");
    return;
  }
  [self beginWaiting];
  if (notify_post(LMNotifyContinue) != NOTIFY_STATUS_OK) [self showFailure:LMLocalized(@"Couldn't request continuation. Close this sheet and try Apply again.")];
}

- (void)showProgress:(uint32_t)done of:(uint32_t)total {
  if (_finished) return;
  _springBoardAnswered = YES;
  if (done == LMProgressFailed) {
    NSString *message;
    switch (total) {
      case LMApplyErrorNoIcons: message = LMLocalized(@"The selection contains no supported artwork. Choose app icons, Control Center icons, or icon effects from the categories."); break;
      case LMApplyErrorRendererUnavailable: message = _dockOnly ? LMLocalized(@"The dock update isn't available. Update Rebug and respring, then try again.") : LMLocalized(@"The renderer isn't available. Update Rebug and respring, then try again."); break;
      case LMApplyErrorRendering: message = LMLocalized(@"Some icons couldn't be rendered. Check that the theme images are readable PNG files and try Apply again."); break;
      case LMApplyErrorReadConfig: message = LMLocalized(@"Couldn't read the saved theme selection. Save your selection and try again."); break;
      case LMApplyErrorNoMatchingApps: message = LMLocalized(@"The selected themes don't contain icons for installed apps."); break;
      case LMApplyErrorStaleAttempt: message = LMLocalized(@"The selection changed after this attempt. Close this sheet and tap Apply again."); break;
      default: message = LMLocalized(@"Couldn't save your changes. Close this sheet and try again."); break;
    }
    [self showFailure:message];
    return;
  }
  if (done == LMProgressPartial) {
    NSDictionary *result = [NSDictionary dictionaryWithContentsOfFile:LMApplyResultPath];
    NSString *generation = result[@"Generation"];
    if (![result[@"State"] isEqual:@"Partial"] || ![generation isKindOfClass:[NSString class]] || !generation.length || ![result[@"SuccessCount"] unsignedIntegerValue]) {
      [self showFailure:LMLocalized(@"Couldn't read the partial result. Close this sheet and try Apply again.")];
      return;
    }
    _partialGeneration = generation;
    [self showFailure:[NSString localizedStringWithFormat:LMLocalized(@"%lu items are ready; %u couldn't be applied. Continue applying to skip the failed items and respring. You can tap Apply later to retry them."), (unsigned long)[result[@"SuccessCount"] unsignedIntegerValue], total]];
    _titleLabel.text = LMLocalized(@"Some items couldn't be applied");
    _continueButton.hidden = NO;
    [self.sheetPresentationController animateChanges:^{
      self.sheetPresentationController.selectedDetentIdentifier = UISheetPresentationControllerDetentIdentifierLarge;
    }];
    return;
  }
  if (done == LMProgressComplete) {
    _finished = YES;
    if (_dockOnly) {
      [[LMConfigStore sharedStore] markDockApplied];
      [_symbol.layer removeAllAnimations];
      _symbol.image = [UIImage systemImageNamed:@"checkmark.circle.fill" withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:52 weight:UIImageSymbolWeightMedium]];
      _symbol.tintColor = [UIColor systemGreenColor];
      _titleLabel.text = LMLocalized(@"Dock updated");
      _statusLabel.text = LMLocalized(@"Only the dock background was updated. Your applied themes and icon labels are unchanged.");
      _progressView.hidden = YES;
      UIButtonConfiguration *close = _closeButton.configuration;
      close.title = LMLocalized(@"Done");
      _closeButton.configuration = close;
      _closeButton.hidden = NO;
      self.modalInPresentation = NO;
      return;
    }
    [[LMConfigStore sharedStore] markApplied];
    _progressView.progress = 1;
    _statusLabel.text = LMLocalized(@"Respringing…");
    return;
  }
  if (!total) {
    _statusLabel.text = _dockOnly ? LMLocalized(@"Updating dock background…") : LMLocalized(@"Refreshing icons…");
    return;
  }
  [_progressView setProgress:(float)done / total animated:YES];
  _statusLabel.text = [NSString localizedStringWithFormat:LMLocalized(@"Rendering icons: %u of %u"), done, total];
}

- (void)showFailureIfSpringBoardIsSilent {
  if (_springBoardAnswered || _finished) return;
  [self showFailure:LMLocalized(@"SpringBoard didn't answer. Make sure Rebug is enabled, respring once, and try again.")];
}

- (void)showFailure:(NSString *)message {
  if (_finished) return;
  _finished = YES;
  [_symbol.layer removeAllAnimations];
  _symbol.image = [UIImage systemImageNamed:@"exclamationmark.triangle.fill" withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:52 weight:UIImageSymbolWeightMedium]];
  _symbol.tintColor = [UIColor systemOrangeColor];
  _progressView.hidden = YES;
  _statusLabel.text = message;
  _closeButton.hidden = NO;
  _continueButton.hidden = YES;
  self.modalInPresentation = NO;
}

@end
