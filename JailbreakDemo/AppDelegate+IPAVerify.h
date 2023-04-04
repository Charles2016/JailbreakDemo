//
//  AppDelegate+IPAVerify.h
//  GDWWNOP
//
//  Created by 1084-Wangcl-Mac on 2022/3/22.
//  Copyright © 2022 cn.mastercom. All rights reserved.
//

#import "AppDelegate.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, GDIPAVerifyType) {
    GDIPAVerifyPass = 0, //包正常
    GDDeviceJailbreak, //设备越狱
    GDCheckO,//Mach-O被篡改
    GDPrepareEnv,//重签打包
    GDFilesIsNotSame//文件被篡改
};

@interface AppDelegate (IPAVerify)

@property (nonatomic, copy) NSString *appIdentifier;
@property (nonatomic, copy) NSString *fileHash;

- (GDIPAVerifyType)verifyIPAPass;//ipa包完整性验证
- (void)showTestFuctionView;//验证ipa包完整性单个功能

@end

NS_ASSUME_NONNULL_END
