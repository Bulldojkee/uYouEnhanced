# Personal AltStore build: iOS 18.5

This branch updates the fork from `a4da77e56e9fe912899b90993e98571eef00e8db`
to upstream `7da4c0a58b146082427860dfd22ae56cabcc4a08` (54 commits), plus
build and artifact-validation fixes. It is a build candidate, not an on-device
stability certification. No decrypted YouTube IPA is included in Git.

## Selected build profile

| Item | Selection |
| --- | --- |
| YouTube input | Decrypted **21.14.4**, checked using `CFBundleShortVersionString` |
| uYou base package | **3.0.4**, patched/rebranded by upstream as unofficial **3.0.5** |
| iSponsorBlock | **Enabled**, pinned upstream 1.3.2 commit `cff4549c0086ebf621ea6950f5bf3fa2911364a5` |
| YTUHD | Disabled by default |
| Device | iOS 18.5; input and final IPA must declare a compatible minimum iOS |
| Build environment | `macos-15-intel`, Xcode 16.4, Theos SDK 18.6, deployment target 16.0 |
| Output | Validated IPA, SHA-256 and build metadata in an Actions artifact, retained 7 days |

Other YouTube versions might work, but this profile deliberately accepts only
21.14.4. A newer app version is not automatically compatible with hooks into
YouTube's internal classes. Change the expected version only after a separate
compatibility review. SDK 18.6 is the compiler SDK; it does not by itself require
iOS 18.6 on the phone.

## Bundle identity and data preservation

The original identifier used by the existing installation is **not yet known**.
The old fork defaults to `com.google.ios.youtube`; that is evidence about its
defaults, not proof of the identifier used for the user's old IPA.

1. Prefer reading `CFBundleIdentifier` from the old IPA that was installed.
2. If obtaining an identifier from the device/AltStore, distinguish the original
   IPA identifier from an identifier rewritten by AltStore during signing. Do
   not blindly paste a signing-team suffix back into the new source IPA.
3. Supply the confirmed original IPA ID to the required `bundle_id` input.
4. Install through the same AltStore/Apple account over the existing app. Do
   not delete the existing app as an update step. Retain a backup before device
   testing; a matching IPA identifier cannot certify signing identity or app
   database migrations.

The workflow passes the ID to Make and cyan, then checks the final main app ID
and extension ID prefixes. It never guesses an ID or resets saved preferences.

## Run the workflow

After reviewing this branch, either merge it or select this branch in the
existing `buildapp.yml` workflow's **Run workflow** selector. If Actions are
disabled for the fork, enable them in its Actions tab first. The workflow file
must also exist on the repository default branch for manual dispatch; this
fork already has `buildapp.yml` there.

Provide a direct HTTPS download URL for your decrypted YouTube 21.14.4 IPA and
the confirmed `bundle_id`. Keep `sdk_version=18.6`, `uyou_version=3.0.4`,
`sponsorblock=true`, `ytuhd=false`, `upload_artifact=true`, and
`create_release=false`. The URL must work without an interactive login from
GitHub's runner. An IPA supplied only as a local attachment must first be made
available to the runner; no upload destination is assumed or created here.

Only `Payload/*` is extracted into a temporary directory after ZIP and Mach-O
validation. The source download stays under `RUNNER_TEMP`. Only the final
validated IPA and build metadata enter the artifact. `.ipa`, `Payload/`, and
the historical `YouTube.zip` intermediate are excluded from Git. The workflow
contains no `git add`, commit, or push step. Masking the URL in step logs does
not make a workflow input a secret; use a download link appropriate for the
repository's visibility.

The final gate verifies the exact version and bundle ID, decrypt status,
resignable extension layout, and actual presence/load references for
iSponsorBlock, YouMute and YTHoldForSpeed. It does not simulate dyld resolution
or execute the application. AltStore supplies the installation signature.

## Compatibility evidence and device checks

- The [21.14.4 release](https://github.com/arichornlover/uYouEnhanced/releases/tag/v21.14.4-3.0.5)
  initially advised leaving iSponsorBlock off. Later
  [September 3 workflow fixes](https://github.com/arichornlover/uYouEnhanced/commit/850e494c0414d8eab1442acab3c49ed93bf2faae)
  and the closed [missing-iSponsorBlock issue #996](https://github.com/arichornlover/uYouEnhanced/issues/996)
  support using current main and explicitly including it. They do not establish
  crash-free behavior on this particular iOS 18.5 device.
- Historical [Shorts-opening reports #900](https://github.com/arichornlover/uYouEnhanced/issues/900)
  implicated Return YouTube Dislikes; the old user's crash cannot be attributed
  to SponsorBlock without its crash log.
- [Issue #995](https://github.com/arichornlover/uYouEnhanced/issues/995)
  reports a separate crash when tapping the uYou **download button inside Shorts**
  on 21.14.4. Opening, swiping and downloading Shorts must be tested separately.
  The report concerns another OS/installation combination. Global version
  spoofing is not enabled by this branch.
- [Home/ad-blocker issue #529](https://github.com/arichornlover/uYouEnhanced/issues/529)
  documents conflicts when Lite and full AdBlock Workaround are enabled
  together. Preserved old settings may retain that combination. If Home gaps
  return, inspect the settings before changing versions: use only one
  workaround; Lite targets video/Shorts ads and can leave Home banner ads.
  [Issue #770](https://github.com/arichornlover/uYouEnhanced/issues/770) concerns
  the user's old 19.21.2 base and recommends checking `Remove YouTube Ads` and
  `Hide Shorts Cells` settings.
- [Issue #990](https://github.com/arichornlover/uYouEnhanced/issues/990) contains
  residual startup-crash reports after HOTFIX3. No universal stability claim is
  made for current upstream.

On the phone, verify that the app updates in place, login/settings/downloads
remain, Home continues loading after repeated scrolling, normal videos play,
Shorts open and swipe, and SponsorBlock skips segments. Test the Shorts download
button separately last. If a failure occurs, record the action, settings and
crash log before changing one option at a time. A diagnostic build can exclude
SponsorBlock with the workflow input; this does not automatically clear its
saved settings.

## Changes beyond upstream

- Add YouMute and YTHoldForSpeed to `SUBPROJECTS`; upstream listed their dylibs
  for injection without building them.
- Pass bundle ID, display name, SDK/target, app version and feature flags as
  explicit Make parameters, including for recursive subprojects.
- Select exactly one built `.ipa`, rather than the newest arbitrary package.
- Pin the runner family, Xcode path, Actions, Theos, theos-jailed, SDK, cyan and
  Safari extension source revisions. Homebrew packages remain resolved at run
  time. Preserve upstream's cyan/extension/icon processing.
- Validate input and final artifacts; make artifact output the default and
  draft-release creation opt-in. Remove the arbitrary old-commit input so that
  workflow and source scripts always come from the same dispatched commit.

## Local validation

Run `python3 -m unittest discover -s Scripts -p test_ipa_preflight.py`.
Thirty synthetic-IPA tests passed during preparation. The workflow also passed
actionlint 1.7.12 without optional shellcheck/pyflakes integrations; Bash syntax
and embedded Python blocks were checked separately. No real input IPA or
confirmed old bundle ID was available, so native compilation, installation,
and iPhone runtime checks remain pending.
