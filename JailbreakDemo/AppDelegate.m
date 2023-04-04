//
//  AppDelegate.m
//  JailbreakDemo
//
//  Created by 1084-Wangcl-Mac on 2023/4/4.
//  Copyright © 2023 Charles2021. All rights reserved.
//

#import "AppDelegate.h"
#import "AppDelegate+IPAVerify.h"

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    //先进行ipa包完整性校验完成才能进入页面，检查顺序：设备越狱->Mach-O被篡改->重签打包->文件被篡改
    if ([self verifyIPAPass] != GDIPAVerifyPass) {
        NSLog(@"请注意，此手机越狱了！！！");
    }
    return YES;
}


#pragma mark - UISceneSession lifecycle


- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options {
    // Called when a new scene session is being created.
    // Use this method to select a configuration to create the new scene with.
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions {
    // Called when the user discards a scene session.
    // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}


@end
