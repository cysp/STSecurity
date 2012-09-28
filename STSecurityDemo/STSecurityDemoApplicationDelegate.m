//
//  STSecurityDemoApplicationDelegate.m
//  STSecurityDemo
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityDemoApplicationDelegate.h"


@implementation STSecurityDemoApplicationDelegate

@synthesize window = _window;
- (void)setWindow:(UIWindow *)window {
	NSAssert(!_window, @"%@ multiple times", NSStringFromSelector(_cmd));
	_window = window;
	[_window makeKeyAndVisible];
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
	UIWindow *window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    window.backgroundColor = [UIColor whiteColor];

	self.window = window;

    return YES;
}

@end
