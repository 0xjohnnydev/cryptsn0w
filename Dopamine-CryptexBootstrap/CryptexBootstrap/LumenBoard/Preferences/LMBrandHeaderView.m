#import "LMBrandHeaderView.h"

@implementation LMBrandHeaderView
- (instancetype)initWithFrame:(CGRect)frame {
  if ((self = [super initWithFrame:frame])) {
    UIView *card = [UIView new];
    card.backgroundColor = [UIColor blackColor];
    card.layer.cornerRadius = 20;
    card.clipsToBounds = YES;
    UIImage *logo = [UIImage imageNamed:@"icon.png" inBundle:LMBundle() compatibleWithTraitCollection:nil];
    UIImageView *image = [[UIImageView alloc] initWithImage:logo];
    image.contentMode = UIViewContentModeScaleAspectFit;
    image.isAccessibilityElement = YES;
    image.accessibilityLabel = @"Rebug iOS by @GenericCoding";
    image.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:image];
    [NSLayoutConstraint activateConstraints:@[
      [image.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:12],
      [image.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-12],
      [image.topAnchor constraintEqualToAnchor:card.topAnchor constant:12],
      [image.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-12],
      [image.heightAnchor constraintEqualToAnchor:image.widthAnchor multiplier:1.0 / 3.0],
    ]];
    _subtitleLabel = [UILabel new];
    _subtitleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    _subtitleLabel.adjustsFontForContentSizeCategory = YES;
    _subtitleLabel.textColor = [UIColor secondaryLabelColor];
    _subtitleLabel.textAlignment = NSTextAlignmentCenter;
    _subtitleLabel.numberOfLines = 0;
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[card, _subtitleLabel]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
      [stack.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
      [stack.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
      [stack.topAnchor constraintEqualToAnchor:self.topAnchor],
      [stack.bottomAnchor constraintEqualToAnchor:self.bottomAnchor],
    ]];
  }
  return self;
}
@end
