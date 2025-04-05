//
//  jailbreak.m
//  Meridian
//
//  Created by Ben Sparkes on 16/02/2018.
//  Copyright © 2018 Ben Sparkes. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>

#include <sys/stat.h>
#include <mach/mach_types.h>

#include "amfi.h"
#include "common.h"
#include "helpers.h"
#include "jailbreak.h"
#include "kernel.h"
#include "offsetdump.h"
#include "offsetfinder.h"
#include "patchfinder64.h"
#include "preferences.h"
#include "root-rw.h"
#include "nonce.h"
#include "nvpatch.h"
#include "v0rtex.h"

#ifdef HEADLESS
extern CFOptionFlags popup(CFStringRef title, CFStringRef text, CFStringRef buttonOne, CFStringRef buttonTwo, CFStringRef buttonThree);
extern int downloadAndExtract(const char *file, const char *path, const char *dir);

static int grabBootstrapFiles(void)
{
    return downloadAndExtract("Meridia2.tar.xz", "/tmp/Meridia2.tar.xz", "/tmp/Meridian");
}
#endif

#define POPUP(title, str, args ...) \
    NSString *nsStr = [NSString stringWithFormat:@str, ##args]; \
    popup(CFSTR(title), (__bridge CFStringRef)nsStr, CFSTR("OK"), NULL, NULL)

#define FAIL(str, args ...) \
    do { \
        LOG(str, ##args); \
        POPUP("spyware fail", str, ##args); \
    } while (0);

NSFileManager *fileMgr;
offsets_t *offsets;
BOOL great_success = FALSE;

int makeShitHappen() {
    int ret = 0;

    uint64_t kernel_task_addr = rk64(offsets->kernel_task + kslide);
    kernprocaddr = rk64(kernel_task_addr + offsets->task_bsd_info);
    kern_ucred = rk64(kernprocaddr + offsets->proc_ucred);

    if (ret == 0) {
        LOG("tfp0: 0x%x", tfp0);
        LOG("kernel_base: 0x%llx", kernel_base);
        LOG("kslide: 0x%llx", kslide);
        LOG("kern_ucred: 0x%llx", kern_ucred);
        LOG("kernprocaddr: 0x%llx", kernprocaddr);
    }

    fileMgr = [NSFileManager defaultManager];

    // set up stuff
    init_patchfinder(NULL);
    ret = init_amfi();
    if (ret != 0) {
        FAIL("failed to initialize amfi methods :/");
        return 1;
    }

    // patch containermanager
    LOG("patching containermanager...");
    ret = patchContainermanagerd();
    if (ret != 0) {
        LOG("failed!");
        return 1;
    }

    // remount root fs
    LOG("remounting rootfs as r/w...");
    ret = remountRootFs();
    if (ret != 0) {
        FAIL("failed to remount the root fs: %d", ret);
        return 1;
    }

    /*      Begin the filesystem fuckery      */

    LOG("some filesytem fuckery...");

    // Remove /meridian in the case of PB's
    if (file_exists("/meridian") == 0 &&
        file_exists("/meridian/.bootstrap") != 0) {
        LOG("removing /meridian dir...");
        [fileMgr removeItemAtPath:@"/meridian" error:nil];
    }

    if (file_exists("/meridian") != 0) {
        ret = mkdir("/meridian", 0755);
        if (ret != 0) {
            FAIL("creating /meridian failed with error %d: %s", errno, strerror(errno));
            return 1;
        }
    }

    if (file_exists("/meridian/logs") != 0) {
        ret = mkdir("/meridian/logs", 0755);
        if (ret != 0) {
            FAIL("creating /meridian/logs failed with error %d: %s", errno, strerror(errno));
            return 1;
        }
    }

    // Bootstrap is not installed/missing, download it 
    if (file_exists("/meridian/.bootstrap") != 0 ||
        file_exists("/meridian/bootstrap/meridian-bootstrap.tar") != 0 ||
        file_exists("/meridian/bootstrap/tar") != 0 ||
        file_exists("/Applications/Zebra.app/Zebra") != 0 ||
        file_exists("/var/lib/dpkg/status") != 0) {
        // clear out temp dir before downloading 
        [fileMgr removeItemAtPath:@"/tmp/Meridian" error:nil];

        // download bootstrap files from remote server
        ret = grabBootstrapFiles();
        if (ret != 0) {
            FAIL("Failed to grab the bootstrap files! ret: %d\nCheck your Internet connection", ret);
            return 1;
        }

        NSString *oldDirectory = [NSString stringWithFormat:@"/tmp/Meridian"];
        NSString *newDirectory = [NSString stringWithFormat:@"/meridian/bootstrap"];

        [fileMgr removeItemAtPath:newDirectory error:nil];
        ret = mkdir([newDirectory UTF8String], 0755);
        if (ret != 0) {
            FAIL("creating %s failed with error %d: %s", [newDirectory UTF8String], errno, strerror(errno));
            return 1;
        }

        // should have our *.tar files in /tmp/Meridian - lets move them
        NSArray *tarFiles = [fileMgr contentsOfDirectoryAtPath:@"/tmp/Meridian" error:nil];
        for (NSString *file in tarFiles) {
            NSString *oldFile = [oldDirectory stringByAppendingPathComponent:file];
            LOG("found file at path: %@", oldFile);

            [fileMgr moveItemAtPath:[oldDirectory stringByAppendingPathComponent:file]
                             toPath:[newDirectory stringByAppendingPathComponent:file]
                              error:nil];
        }
    }
    
    LOG("listing files...");

    NSArray *dirs = [fileMgr contentsOfDirectoryAtPath:@"/meridian/bootstrap" error:nil];
    for (NSString *filename in dirs) {
        NSString *filepath = [[NSString stringWithFormat:@"/meridian/bootstrap"] stringByAppendingPathComponent:filename];
        LOG("found bootstrap file: %@", filepath);
    }

    ret = chmod("/meridian/bootstrap/tar", 0755);
    if (ret != 0) {
        FAIL("chmod(755)'ing /meridian/bootstrap/tar failed with error %d: %s", errno, strerror(errno));
        return 1;
    }

    ret = inject_trust("/meridian/bootstrap/tar");
    if (ret != 0) {
        FAIL("injecting trust to /meridian/bootstrap/tar failed with retcode %d", ret);
        return 1;
    }

    // extract meridian-bootstrap
    LOG("extracting meridian files...");
    ret = extract_bundle_tar("/meridian/bootstrap/meridian-bootstrap.tar");
    if (ret != 0) {
        FAIL("extracting meridian files failed, err: %d", ret);
        return 1;
    }

    dirs = [fileMgr contentsOfDirectoryAtPath:@"/meridian" error:nil];
    for (NSString *filename in dirs) {
        NSString *filepath = [[NSString stringWithFormat:@"/meridian"] stringByAppendingPathComponent:filename];
        LOG("found meridian file: %@", filepath);
    }

    // dump offsets to file for later use (/meridian/offsets.plist)
    dumpOffsetsToFile(offsets, kernel_base, kslide, kernprocaddr);
    
    // load prefs from /meridian/preferences.plist file 
    initAllPreferences();

    // patch amfid
    LOG("patching amfid...");
    ret = defecateAmfi();
    if (ret != 0) {
        if (ret > 0) {
            FAIL("failed to patch amfid - %d tries", ret);
            return 1;
        }

        FAIL("patching amfid failed! code: %d", ret);
        return 1;
    }

    // touch .cydia_no_stash
    touch_file("/.cydia_no_stash");

    // extract bootstrap (if not already extracted)
    if (file_exists("/meridian/.bootstrap") != 0) {
        popup(CFSTR("Installation"), CFSTR("Downloading bootstrap, this may take a while. Press OK to continue"), CFSTR("OK"), NULL, NULL);
        LOG("extracting bootstrap...");
        int exitCode = 0;
        ret = extractBootstrap(&exitCode);

        if (ret != 0) {
            switch (ret) {
                case 1:
                    FAIL("failed to extract system-base.tar");
                    break;
                case 2:
                    FAIL("failed to extract installer-base.tar");
                    break;
                case 3:
                    FAIL("failed to extract dpkgdb-base.tar");
                    break;
                case 4:
                    FAIL("failed to extract cydia-base.tar");
                    break;
                case 5:
                    FAIL("failed to extract optional-base.tar");
                    break;
                case 6:
                    FAIL("failed to run uicache!");
                    break;
            }
            LOG("exit code: %d", exitCode);

            return 1;
        }

        LOG("done!");
    }

    if (StartDropbear)
    {
        // launch dropbear
        LOG("launching dropbear...");
        ret = launchDropbear();
        if (ret != 0) {
            FAIL("failed to launch dropbear! ret: %d", ret);
            return 1;
        }
    }

    // launch substrate if it exists & tweaks are enabled
    if (file_exists("/usr/libexec/substrate") == 0 &&
        TweaksEnabled)
    {
        ret = execprog("/usr/libexec/substrate", NULL);
        if (ret != 0)
        {
            FAIL("Failed to launch substrate! Restart the device and try again. err: %d", ret);
            return 1;
        }
    }

    // load pspawn
    LOG("loading pspawn...");
    ret = startJailbreakd();
    if (ret != 0) {
        if (ret > 0) {
            LOG("failed to load pspawn! err: %d", ret);
            return 1;
        }

        FAIL("failed to load pspawn! err: %d", ret);
        return 1;
    }

    // patch com.apple.System.boot-nonce
    LOG("patching boot-nonce...");
    ret = nvpatch("com.apple.System.boot-nonce");
    if (ret != 0) {
        FAIL("failed to set boot-nonce, ret: %d", ret);
        return 1;
    }

    // Set new nonce (if required)
    const char *current_nonce = copy_boot_nonce();
    if (current_nonce == NULL ||
        strcmp(current_nonce, BootNonce) != 0) {
        LOG("setting boot-nonce...");

        set_boot_nonce(BootNonce);

        LOG("done!");
    }

    if (current_nonce != NULL) {
        free((void *)current_nonce);
    }

    if (StartLaunchDaemons)
    {
        // load launchdaemons
        LOG("loading launchdaemons...");
        ret = loadLaunchDaemons();
        if (ret != 0) {
            FAIL("failed to load launchdaemons, ret: %d", ret);
            return 1;
        }
    }

    if (file_exists("/.meridian_installed") != 0) {
        touch_file("/.meridian_installed");
    }

    great_success = TRUE;

    LOG("reloading userland...");
    ret = execprog("/meridian/nohup", (const char **)&(const char*[]) {
        "/meridian/nohup",
        "/meridian/ldrestart",
        NULL
    });
    if (ret != 0) {
        FAIL("Device is now jailbroken, but failed to launch /meridian/ldrestart, ret: %d. Try opening Zebra anyway", ret);
        return 1;
    }

    LOG("hanging for ldrestart...");
    sleep(10);

    return 0;
}

kern_return_t callback(task_t kern_task, kptr_t kbase, void *cb_data) {
    tfp0 = kern_task;
    kernel_base = kbase;
    kslide = kernel_base - 0xFFFFFFF007004000;

    return KERN_SUCCESS;
}

int patchContainermanagerd() {
    uint64_t cmgr = find_proc_by_name("containermanager");
    if (cmgr == 0) {
        LOG("unable to find containermanager!");
        return 1;
    }

    wk64(cmgr + 0x100, kern_ucred);
    return 0;
}

int remountRootFs() {
    NSOperatingSystemVersion osVersion = [[NSProcessInfo processInfo] operatingSystemVersion];
    int pre103 = osVersion.minorVersion < 3 ? 1 : 0;
    LOG("pre130: %d", pre103);

    int rv = mount_root(kslide, offsets->root_vnode, pre103);
    if (rv != 0) {
        return 1;
    }

    return 0;
}

void setUpSymLinks() {
    struct stat file;
    stat("/Library/MobileSubstrate/DynamicLibraries", &file);

    if (file_exists("/Library/MobileSubstrate/DynamicLibraries") == 0 &&
        file_exists("/usr/lib/tweaks") == 0 &&
        S_ISLNK(file.st_mode)) {
        return;
    }

    // By the end of this check, /usr/lib/tweaks should exist containing any
    // tweaks (if applicable), and /Lib/MobSub/DynLib should NOT exist
    if (file_exists("/Library/MobileSubstrate/DynamicLibraries") == 0 &&
        file_exists("/usr/lib/tweaks") != 0) {
        // Move existing tweaks folder to /usr/lib/tweaks
        [fileMgr moveItemAtPath:@"/Library/MobileSubstrate/DynamicLibraries" toPath:@"/usr/lib/tweaks" error:nil];
    } else if (file_exists("/Library/MobileSubstrate/DynamicLibraries") == 0 &&
               file_exists("/usr/lib/tweaks") == 0) {
        // Move existing tweaks to /usr/lib/tweaks and delete the MobSub folder
        NSArray *fileList = [fileMgr contentsOfDirectoryAtPath:@"/Library/MobileSubstrate/DynamicLibraries" error:nil];
        for (NSString *item in fileList) {
            NSString *fullPath = [NSString stringWithFormat:@"/Library/MobileSubstrate/DynamicLibraries/%@", item];
            [fileMgr moveItemAtPath:fullPath toPath:@"/usr/lib/tweaks" error:nil];
        }
        [fileMgr removeItemAtPath:@"/Library/MobileSubstrate/DynamicLibraries" error:nil];
    } else if (file_exists("/Library/MobileSubstrate/DynamicLibraries") != 0 &&
               file_exists("/usr/lib/tweaks") != 0) {
        // Just create /usr/lib/tweaks - /Lib/MobSub/DynLibs doesn't exist
        mkdir("/Library/MobileSubstrate", 0755);
        mkdir("/usr/lib/tweaks", 0755);
    } else if (file_exists("/Library/MobileSubstrate/DynamicLibraries") != 0 &&
               file_exists("/usr/lib/tweaks") == 0) {
        // We should be fine in this case
        mkdir("/Library/MobileSubstrate", 0755);
    }

    // Symlink it!
    symlink("/usr/lib/tweaks", "/Library/MobileSubstrate/DynamicLibraries");
}

int extractBootstrap(int *exitCode) {
    int rv;

    // extract system-base.tar
    rv = extract_bundle_tar("/meridian/bootstrap/system-base.tar");
    if (rv != 0) {
        *exitCode = rv;
        return 1;
    }

    // extract installer-base.tar
    rv = extract_bundle_tar("/meridian/bootstrap/installer-base.tar");
    if (rv != 0) {
        *exitCode = rv;
        return 2;
    }

    if (file_exists("/private/var/lib/dpkg/status") != 0) {
        [fileMgr removeItemAtPath:@"/private/var/lib/dpkg" error:nil];
        [fileMgr removeItemAtPath:@"/Library/dpkg"         error:nil];

        rv = extract_bundle_tar("/meridian/bootstrap/dpkgdb-base.tar");
        if (rv != 0) {
            *exitCode = rv;
            return 3;
        }
    }

    // extract cydia-base.tar
    rv = extract_bundle_tar("/meridian/bootstrap/cydia-base.tar");
    if (rv != 0) {
        *exitCode = rv;
        return 4;
    }

    // extract optional-base.tar
    rv = extract_bundle_tar("/meridian/bootstrap/optional-base.tar");
    if (rv != 0) {
        *exitCode = rv;
        return 5;
    }

    enableHiddenApps();

    touch_file("/meridian/.bootstrap");

    rv = uicache();
    if (rv != 0) {
        *exitCode = rv;
        return 6;
    }

    return 0;
}

int defecateAmfi() {
    // trust our payload
    int ret = inject_trust("/meridian/amfid_payload.dylib");
    if (ret != 0) return -1;

    unlink("/var/tmp/amfid_payload.alive");

    pid_t pid = get_pid_for_name("amfid");
    if (pid < 0) {
        LOG("amfid is not running? launching it :^)");
        execprog("/meridian/nohup", NULL);
        sleep(3);

        pid = get_pid_for_name("amfid");
        if (pid < 0) {
            return -2;
        }
    }

    ret = inject_library(pid, "/meridian/amfid_payload.dylib");
    if (ret != 0) return -3;

    int tries = 0;
    while (file_exists("/var/tmp/amfid_payload.alive") != 0) {
        if (tries >= 100) {
            LOG("failed to patch amfid (%d tries)", tries);
            return tries;
        }

        LOG("waiting for amfid patch...");
        usleep(100000); // 0.1 sec
        tries++;
    }

    return 0;
}

int launchDropbear() {
    NSMutableArray *args = [NSMutableArray arrayWithCapacity:11];

    [args addObject:@"/meridian/dropbear/dropbear"];

    switch (DropbearPortSetting)
    {
        case DropbearPort22:
            [args addObjectsFromArray:@[@"-p", @"22"]];
            break;
        case DropbearPort2222:
            [args addObjectsFromArray:@[@"-p", @"2222"]];
            break;
        case DropbearPortBoth:
            [args addObjectsFromArray:@[@"-p", @"22", @"-p", @"2222"]];
            break;
    }

    [args addObjectsFromArray:@[@"-F", @"-R", @"-E", @"-m", @"-S", @"/"]];

    NSMutableDictionary *newPrefs = [NSMutableDictionary dictionaryWithContentsOfFile:@"/meridian/dropbear/dropbear.plist"];
    
    newPrefs[@"ProgramArguments"] = args;
    NSLog(@"launching dropbear with args %@", args);

    [newPrefs writeToFile:@"/meridian/dropbear/dropbear.plist" atomically:FALSE];

    return start_launchdaemon("/meridian/dropbear/dropbear.plist");
}

void setUpSubstitute() {
    // link CydiaSubstrate.framework -> /usr/lib/libsubstrate.dylib
    if (file_exists("/Library/Frameworks/CydiaSubstrate.framework") == 0) {
        [fileMgr removeItemAtPath:@"/Library/Frameworks/CydiaSubstrate.framework" error:nil];
    }
    mkdir("/Library/Frameworks", 0755);
    mkdir("/Library/Frameworks/CydiaSubstrate.framework", 0755);
    symlink("/usr/lib/libsubstrate.dylib", "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
}

int startJailbreakd() {
    int rv;

    rv = inject_trust("/usr/lib/pspawn_hook.dylib");
    if (rv != 0) return 2;

    // inject pspawn_hook.dylib to launchd
    rv = inject_library(1, "/usr/lib/pspawn_hook.dylib");
    if (rv != 0) return 3;

    return 0;
}

int loadLaunchDaemons() {
    NSArray *daemons = [fileMgr contentsOfDirectoryAtPath:@"/Library/LaunchDaemons" error:nil];
    for (NSString *file in daemons) {
        NSString *path = [NSString stringWithFormat:@"/Library/LaunchDaemons/%@", file];
        LOG("found launchdaemon: %@", path);
        chmod([path UTF8String], 0755);
        chown([path UTF8String], 0, 0);
    }

    return start_launchdaemon("/Library/LaunchDaemons");
}

void enableHiddenApps() {
    // enable showing of system apps on springboard
    // this is some funky killall stuff tho
    killall("cfprefsd", "-SIGSTOP");
    NSMutableDictionary* md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
    killall("cfprefsd", "-9");
}
