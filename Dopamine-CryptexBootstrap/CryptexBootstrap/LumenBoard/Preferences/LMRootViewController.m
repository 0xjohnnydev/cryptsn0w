#import "LMRootViewController.h"
#import "LMThemesViewController.h"

@implementation LMRootViewController {
  LMThemesViewController *_themesController;
}

- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = LMDisplayName;
  self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
  self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
  self.view.tintColor = [UIColor systemRedColor];
  _themesController = [LMThemesViewController new];
  [self addChildViewController:_themesController];
  UIView *content = _themesController.view;
  content.translatesAutoresizingMaskIntoConstraints = NO;
  [self.view addSubview:content];
  UIView *actionBar = [UIView new];
  actionBar.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
  actionBar.translatesAutoresizingMaskIntoConstraints = NO;
  [self.view addSubview:actionBar];
  UIButton *apply = _themesController.applyButton;
  apply.translatesAutoresizingMaskIntoConstraints = NO;
  [actionBar addSubview:apply];
  [NSLayoutConstraint activateConstraints:@[
    [content.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
    [content.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    [content.topAnchor constraintEqualToAnchor:self.view.topAnchor],
    [content.bottomAnchor constraintEqualToAnchor:actionBar.topAnchor],
    [actionBar.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
    [actionBar.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    [actionBar.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    [apply.leadingAnchor constraintEqualToAnchor:actionBar.safeAreaLayoutGuide.leadingAnchor constant:20],
    [apply.trailingAnchor constraintEqualToAnchor:actionBar.safeAreaLayoutGuide.trailingAnchor constant:-20],
    [apply.topAnchor constraintEqualToAnchor:actionBar.topAnchor constant:12],
    [apply.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-12],
    [apply.heightAnchor constraintGreaterThanOrEqualToConstant:52],
  ]];
  [_themesController didMoveToParentViewController:self];
  // Settings owns the navigation stack and its Back button.
  self.navigationItem.rightBarButtonItems = _themesController.navigationItem.rightBarButtonItems;
}

- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];
  [self.navigationController setToolbarHidden:YES animated:animated];
}

- (void)viewWillDisappear:(BOOL)animated {
  [super viewWillDisappear:animated];
  [self.navigationController setToolbarHidden:YES animated:animated];
}

@end
