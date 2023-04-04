//
//  AppDelegate+IPAVerify.m
//  GDWWNOP
//
//  Created by 1084-Wangcl-Mac on 2022/3/22.
//  Copyright © 2022 cn.mastercom. All rights reserved.
//

#import "AppDelegate+IPAVerify.h"
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <dlfcn.h>
#include <CommonCrypto/CommonDigest.h>

static NSString *appIdentifierKey = @"appIdentifierKey";
static NSString *fileHashKey = @"fileHashKey";

@implementation AppDelegate (IPAVerify)

- (void)setAppIdentifier:(NSString *)appIdentifier {
    objc_setAssociatedObject(self, &appIdentifierKey, appIdentifier, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (NSString *)appIdentifier {
    return objc_getAssociatedObject(self, &appIdentifierKey);
}

- (void)setFileHash:(NSString *)fileHash {
    objc_setAssociatedObject(self, &fileHashKey, fileHash, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (NSString *)fileHash {
    return objc_getAssociatedObject(self, &fileHashKey);
}

- (GDIPAVerifyType)verifyIPAPass {
    GDIPAVerifyType type = GDIPAVerifyPass;
#if DEBUG

#else
    //设备是否越狱校验
    if ([self isDeviceJailbreak]) {
        type = GDDeviceJailbreak;
    } else
#endif
    if ([self checkO]) {
        //Mach-O文件否被篡改校验
        type = GDCheckO;
    } else if ([self prepareEnv]) {
        //防止重签打包验证
        type = GDPrepareEnv;
    } else if ([self filesMD5Verify]) {
        //文件被篡改校验
        type = GDFilesIsNotSame;
    }
    
    if (type != GDIPAVerifyPass) {
        //为了显示欢迎页和验证不通过弹出框
        
    }
    return type;
}

#pragma mark - 设备是否越狱校验
// 常见越狱文件
const char *device_pathes[] = {
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/User/Applications/"
};

char *printEnvGDJ(void) {
    return getenv("DYLD_INSERT_LIBRARIES");
}

static NSSet *sDylibSet ; // 需要检测的动态库

/** 当前设备是否越狱 */
- (BOOL)isDeviceJailbreak {
    // 检查是否可以写入系统文件
    NSError *error;
    NSString *stringToWrite = @"Jailbreak Test";
    [stringToWrite writeToFile:@"/private/jailbreak_test.txt" atomically:YES encoding:NSUTF8StringEncoding error:&error];
    
    if (!error) {
        //删除测试文件
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/jailbreak_test.txt" error:nil];
        return YES;
    }
    
    //检查是否存在越狱文件路径
    NSArray *jailbreakFilePaths = @[@"/Applications/Cydia.app",
                                    @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                                    @"/bin/bash",
                                    @"/usr/sbin/sshd",
                                    @"/etc/apt",
                                    @"/User/Applications/"];
    for (NSString *path in jailbreakFilePaths) {
       if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
           return YES;
       }
    }
    //用C函数的方法检查越狱文件路径是否存在
    for (int i = 0; i < sizeof(device_pathes) / sizeof(char *); i++) {
        struct stat stat_info;
        if (0 == stat(device_pathes[i], &stat_info)) {
            return YES;
        }
    }

    //通过私有api获取bundleId，然后检测插件关键字，若上架App Store则需要对api的字符做加解密操作，否则可能被拒
    Class LSApplicationWorkspace_Class = NSClassFromString(@"LSApplicationWorkspace");
    NSObject *workspace = [LSApplicationWorkspace_Class performSelector:NSSelectorFromString(@"defaultWorkspace")];
    NSArray *appList = [workspace performSelector:NSSelectorFromString(@"allApplications")];
    NSString *appStr = @"";
    for (id app in appList) {
        NSString *appId = [app performSelector:NSSelectorFromString(@"applicationIdentifier")];
        if (appStr.length) {
            appStr = [appStr stringByAppendingFormat:@"|%@", appId];
        } else {
            appStr = [appStr stringByAppendingString:appId];
        }
    }
    NSArray *appIds = @[@"Cydia", @"Sileo", @"Zebra", @"AFC2", @"AppSync", @"LibertyLite", @"Liberty Lite", @"OTADisabler"];
    for (NSString *tempStr in appIds) {
        if ([appStr.uppercaseString containsString:tempStr.uppercaseString]) {
            return YES;
        }
    }
    
    sDylibSet  = [NSSet setWithObjects:
         @"/usr/lib/CepheiUI.framework/CepheiUI",
         @"/usr/lib/libsubstitute.dylib",
         @"/usr/lib/substitute-inserter.dylib",
         @"/usr/lib/substitute-loader.dylib",
         @"/usr/lib/substrate/SubstrateLoader.dylib",
         @"/usr/lib/substrate/SubstrateInserter.dylib",
         @"/Library/MobileSubstrate/MobileSubstrate.dylib",
         @"/Library/MobileSubstrate/DynamicLibraries/0Shadow.dylib",nil];
    //判断是否存在越狱文件，使用stat通过检测一些越狱后的关键文件是否可以访问来判断是否越狱，hook stat 方法和dladdr可以绕过
    int ret ;
    Dl_info dylib_info;
    int (*func_stat)(const char *, struct stat *) = stat;
    if ((ret = dladdr(func_stat, &dylib_info))) {
        NSString *fName = [NSString stringWithUTF8String: dylib_info.dli_fname];
        if(![fName isEqualToString:@"/usr/lib/system/libsystem_kernel.dylib"]){
            return YES;
        }
    }
    
    //判断是否注入了动态库
    unsigned int outCount = 0;
    const char **images =  objc_copyImageNames(&outCount);
    for (int i = 0; i < outCount; i++) {
      NSLog(@"%s\n", images[i]);
    }

    int i = 0;
    while(true) {
      //hook _dyld_get_image_name方法可以绕过
      const char *name = _dyld_get_image_name(i++);
      if(name == NULL){
          break;
      }
      
      if (name != NULL) {
        NSString *libName = [NSString stringWithUTF8String:name];
        if ([sDylibSet containsObject:libName]) {
          return YES;
        }
      }
    }
    
    //判断是否存在cydia应用
    if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]){
        NSLog(@"此设备越狱!");
        return YES;
    }
    
    //读取环境变量
if(printEnvGDJ()){
    NSLog(@"此设备越狱!");
    return YES;
}
    
    NSLog(@"此设备没有越狱");
    return NO;
}

#pragma mark - 判断Mach-O文件否被篡改
- (BOOL)checkO {
    NSBundle *bundle = [NSBundle mainBundle];
    NSDictionary *info = [bundle infoDictionary];
    if ([info objectForKey: @"SignerIdentity"] != nil){
        //存在这个key，则说明被二次打包了
        return YES;
    }
    return NO;
}

#pragma mark - 防止重签打包验证
- (BOOL)prepareEnv {
    NSString *embeddedPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:embeddedPath]) {
        NSString *embeddedProvisioning = [NSString stringWithContentsOfFile:embeddedPath encoding:NSASCIIStringEncoding error:nil];
        NSArray *embeddedProvisioningLines = [embeddedProvisioning componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

        for (int i = 0; i < [embeddedProvisioningLines count]; i++) {
            if ([[embeddedProvisioningLines objectAtIndex:i] rangeOfString:@"application-identifier"].location != NSNotFound) {
                NSInteger fromPosition = [[embeddedProvisioningLines objectAtIndex:i+1] rangeOfString:@"<string>"].location+8;
                NSInteger toPosition = [[embeddedProvisioningLines objectAtIndex:i+1] rangeOfString:@"</string>"].location;
                NSRange range;
                range.location = fromPosition;
                range.length = toPosition - fromPosition;
                NSString *fullIdentifier = [[embeddedProvisioningLines objectAtIndex:i+1] substringWithRange:range];
                NSArray *identifierComponents = [fullIdentifier componentsSeparatedByString:@"."];
                NSString *appIdentifier = [identifierComponents firstObject];
                self.appIdentifier = appIdentifier;
                // 对比签名ID
                if ([appIdentifier caseInsensitiveCompare:@"ZDPEKFXXXX"] != NSOrderedSame && ![appIdentifier isEqualToString:@"CDDDDDDD"]) {
                    self.appIdentifier = [NSString stringWithFormat:@"appIdentifier:ZDPEKFXXXX appIdentifierN:%@", appIdentifier];
                    return YES;
                }
                break;
            }
        }
    }
    return NO;
}

#pragma mark - 文件被篡改校验
- (BOOL)filesMD5Verify {
    NSMutableArray *allImages = @[].mutableCopy;
    //获取app目录下的所有子文件，并取AppIcon和LaunchImage相关图片做标记对比hash值
    NSString *bundlePath = [[NSBundle mainBundle] resourcePath];
    NSArray *dirArray = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundlePath error:nil];
    for (NSString *fileName in dirArray) {
        if ([fileName containsString:@".png"] && ([fileName containsString:@"AppIcon"] || [fileName containsString:@"LaunchImage"])) {
            [allImages addObject:fileName];
        }
    }
    if (allImages.count == 0) {
        return YES;
    }
    
   /*验证文件md5时先取出来一遍，以便好记录
    NSMutableDictionary *md5Dic = @{}.mutableCopy;
    for (int i = 0; i < allImages.count; i++) {
        NSString *name = allImages[i];
        NSString *md5N = [self getFileMD5WithPath:[NSString stringWithFormat:@"%@/%@", bundlePath, name]];
        [md5Dic setValue:md5N forKey:name];
    }
    NSLog(@"md5Dic.JSONString:\n%@", md5Dic.JSONString);*/
    //IPA包中的图片校验
    NSDictionary *files = @{@"LaunchImage-800-667h@2x.png":@"640fa9b1eea2c213df76d1b46b2541cf",
                            @"LaunchImage-800-Portrait-736h@3x.png":@"d24d66af2ba194200435928ede112163",
                            @"LaunchImage-1100-Portrait-2436h@3x.png":@"26e39ef03140d787d164cf22cf63c8fd",
                            @"LaunchImage-1200-Portrait-1792h@2x.png":@"f8cb1e88aee6f6d4c8f19ab49e8ac126",
                            @"LaunchImage-1200-Portrait-2688h@3x.png":@"95ec433723282568337ca61a35576819",
                            /*以下生成的图片貌似会变，试过了打包出来跟模拟器运行的，md5对不上,需要进一步测试
                            @"AppIcon20x20@2x.png":@"6bbd2d4005f697d92edf0c3e08c8f9c2",
                            @"AppIcon20x20@3x.png":@"e10f24814b6d77c8c7deda214f2b3b22",
                            @"AppIcon29x29@2x.png":@"77ea8da0a59223c319e9409b23ea3549",
                            @"AppIcon29x29@3x.png":@"5e5dfd91aa50abe3d0699ad503315220",
                            @"AppIcon40x40@2x.png":@"e9c07d7049615733226c0d6774e80fc3",
                            @"AppIcon40x40@3x.png":@"31a4a8422afbbd7757f99c15c0ba1683",
                            @"AppIcon60x60@2x.png":@"31a4a8422afbbd7757f99c15c0ba1683",
                            @"AppIcon60x60@3x.png":@"57456909d87f9f741254a43a05af7cc7",
                            @"LaunchImage-700-568h@2x.png":@"7538d4cc1befa8e1fc3481755585d551",
                            @"LaunchImage@2x.png":@"c6e89cc76e226fcfb67b2ddb02ff9bf4",
                            @"LaunchImage-568h@2x.png":@"2fbf6ed2b1c520e7884bad758aae473f",
                            @"AppIcon57x57@2x.png":@"e619f57770cec363936acd40576dda7c",
                            @"LaunchImage-700@2x.png":@"4d6c1e22746b26a118ee5b3f3bda80db",*/
                            };
    
    BOOL isChange = NO;
    for (int i = 0; i < allImages.count; i++) {
        NSString *name = allImages[i];
        if (![files.allKeys containsObject:name]) {
            //若files中没有对应的key值则跳过校验
            continue;
        }
        NSString *md5 = files[name];
        NSString *md5N = [self getFileMD5WithPath:[NSString stringWithFormat:@"%@/%@", bundlePath, name]];
        if (![md5 isEqual:md5N]) {
            NSLog(@"%@ md5:%@ md5N:%@", name, md5, md5N);
            self.fileHash = [NSString stringWithFormat:@"%@ md5:%@ md5N:%@", name, md5, md5N];
            isChange = YES;
            break;
        }
    }
    return isChange;
}

#pragma mark - 验证ipa包完整性单个功能
- (void)showTestFuctionView {
    UIView *view = [[UIView alloc] init];
    view.backgroundColor = UIColor.whiteColor;
    [self.window addSubview:view];
    CGFloat buttonH = 44;
    CGFloat viewH = 10 + (buttonH + 10) * 4;
    CGFloat viewT = (self.window.frame.size.height - viewH) / 2;
    CGFloat viewW = [UIScreen mainScreen].bounds.size.width - 20;
    view.frame = CGRectMake(10, viewT, viewW, viewH);
    
    NSArray *buttons = @[@"设备是否越狱校验", @"判断Mach-O文件否被篡改", @"防止重签打包验证", @"文件被篡改校验"];
    
    for (int i = 0; i < 4; i++) {
        UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
        button.tag = 202203240 + i;
        button.titleLabel.font = [UIFont systemFontOfSize:13];
        [button setTitle:buttons[i] forState:UIControlStateNormal];
        [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        [button addTarget:self action:@selector(buttonAction:) forControlEvents:UIControlEventTouchUpInside];
        [view addSubview:button];
        button.backgroundColor = UIColor.magentaColor;
        button.frame = CGRectMake(10, 10 + i * (buttonH + 10), viewW - 20, buttonH);
    }
}

#pragma mark - buttonActions
- (void)buttonAction:(UIButton *)button {
    NSInteger index = button.tag - 202203240;
    NSArray *titles = @[@"设备是否越狱验证", @"Mach-O文件是否被篡改验证", @"是否重签打包验证", @"文件是否被篡改验证"];
    NSArray *messages = @[@"安装包安全性检测正常", @"检测到当前设备为越狱设备，越狱环境存在安全风险！应用即将退出！", @"此安装包可能存在反编译风险，请从官方途径下载安装包使用!", @"检测到当前安装包文件被篡改，存在安全风险！应用即将退出！", @"检测到当前安装包内容被篡改，存在安全风险！应用即将退出！"];
    
    GDIPAVerifyType type = 0;
    NSString *desc = @"";

    //设备是否越狱校验
    if (index == 0 && [self isDeviceJailbreak]) {
        type = GDDeviceJailbreak;
    }
        
    //Mach-O文件否被篡改校验
    if (index == 1 && [self checkO]) {
        type = GDCheckO;
    }
    
    //防止重签打包验证
    if (index == 2 && [self prepareEnv]) {
        type = GDPrepareEnv;
        desc = [NSString stringWithFormat:@"appIdentifier=%@，", self.appIdentifier];
    }
    
    //文件被篡改校验
    if (index == 3 && [self filesMD5Verify]) {
        type = GDFilesIsNotSame;
        desc = [NSString stringWithFormat:@"fileHash=%@，", self.fileHash];
    }
    
    /*[GDPopupAlertView showInView:self.window title:titles[index] message:[NSString stringWithFormat:@"%@%@", desc, messages[type]] buttonTitleList:@[@"知道了"] clickFooterButtonBlock:^(GDPopupBottomButtonView *showView, NSUInteger index, id concernContentData) {
    }];*/
}


#define FileHashDefaultChunkSizeForReadingData 1024*8
- (NSString*)getFileMD5WithPath:(NSString *)path {
    return (__bridge_transfer NSString *)FileMD5HashCreateWithPath((__bridge CFStringRef)path, FileHashDefaultChunkSizeForReadingData);
}

CFStringRef FileMD5HashCreateWithPath(CFStringRef filePath, size_t chunkSizeForReadingData) {
    // Declare needed variables
    CFStringRef result = NULL;
    CFReadStreamRef readStream = NULL;
    // Get the file URL
    CFURLRef fileURL =
    CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)filePath, kCFURLPOSIXPathStyle, (Boolean)false);
    if (!fileURL) goto done;
    // Create and open the read stream
    readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault, (CFURLRef)fileURL);
    if (!readStream) goto done;
    bool didSucceed = (bool)CFReadStreamOpen(readStream);
    if (!didSucceed) goto done;
    // Initialize the hash object
    CC_MD5_CTX hashObject;
    CC_MD5_Init(&hashObject);
    // Make sure chunkSizeForReadingData is valid
    if (!chunkSizeForReadingData) {
        chunkSizeForReadingData = FileHashDefaultChunkSizeForReadingData;
    }
    // Feed the data to the hash object
    bool hasMoreData = true;
    while (hasMoreData) {
        uint8_t buffer[chunkSizeForReadingData];
        CFIndex readBytesCount = CFReadStreamRead(readStream,(UInt8 *)buffer,(CFIndex)sizeof(buffer));
        if (readBytesCount == -1) break;
        if (readBytesCount == 0) {
            hasMoreData = false;
            continue;
        }
        CC_MD5_Update(&hashObject,(const void *)buffer,(CC_LONG)readBytesCount);
    }
    
    // Check if the read operation succeeded
    didSucceed = !hasMoreData;
    // Compute the hash digest
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(digest, &hashObject);
    // Abort if the read operation failed
    if (!didSucceed) goto done;
    // Compute the string result
    char hash[2 * sizeof(digest) + 1];
    for (size_t i = 0; i < sizeof(digest); ++i) {
        snprintf(hash + (2 * i), 3, "%02x", (int)(digest[i]));
    }
    result = CFStringCreateWithCString(kCFAllocatorDefault,(const char *)hash,kCFStringEncodingUTF8);
done:
    if (readStream) {
        CFReadStreamClose(readStream);
        CFRelease(readStream);
    }
    
    if (fileURL) {
        CFRelease(fileURL);
    }
    return result;
}

@end
