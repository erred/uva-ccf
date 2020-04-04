# install mac os in kvm

following guide:

https://github.com/foxlet/macOS-Simple-KVM
https://passthroughpo.st/new-and-improved-mac-os-tutorial-part-1-the-basics/

User / UserPassword

FF 2020-02-10-09-39-12-mozilla-central

https://www.microsoft.com/en-us/research/project/detection-of-javascript-based-malware/
https://www.microsoft.com/en-us/research/publication/nofus-automatically-detecting-string-fromcharcode32-obfuscated-tolowercase-javascript-code/

https://www.sophos.com/en-us/security-news-trends/security-trends/malicious-javascript.aspx
http://www.malware-traffic-analysis.net/blog-entries.html

https://awesomeopensource.com/project/InQuest/malware-samples
https://github.com/RamadhanAmizudin/malware
https://github.com/HynekPetrak/javascript-malware-collection
https://github.com/ytisf/theZoo
https://github.com/fabrimagic72/malware-samples
https://github.com/wolfvan/some-samples
https://github.com/0x48piraj/MalWAReX
https://github.com/drbeni/malquarium
https://github.com/mstfknn/malware-sample-library

https://bugzilla.mozilla.org/show_bug.cgi?id=1609815
FF first release in january

https://reverseengineering.stackexchange.com/questions/1436/analyzing-highly-obfuscated-javascript
https://resources.infosecinstitute.com/analyzing-javascript/
https://www.joesecurity.org/blog/7492960968739667986
https://medium.com/@eaugusto/documents-pdfs-js-and-shellcode-analyzing-malicious-javascript-samples-with-box-js-and-53f264f37b2c
https://css-tricks.com/anatomy-of-a-malicious-script-how-a-website-can-take-over-your-browser/
https://box.js.org/
https://www.researchgate.net/publication/283098369_JSDC_A_Hybrid_Approach_for_JavaScript_Malware_Detection_and_Classification
https://www.researchgate.net/publication/318074514_Detection_of_Malicious_JavaScript_Code_in_Web_Pages
https://github.com/HynekPetrak/malware-jail
https://github.com/rshipp/awesome-malware-analysis
http://www.relentless-coding.com/projects/jsdetox/
https://github.com/urule99/jsunpack-n
http://malzilla.sourceforge.net/

https://www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452

```
git log --grep NIGHTLY
commit bc27944e4d39d82ee120730a9ce05834abdde3b3
Author: ffxbld <release@mozilla.com>
Date:   Mon Jan 6 15:50:11 2020 +0000

    No bug - Tagging mozilla-central d5843cae64d30255b242d051888e99bef3de5c05 with FIREFOX_NIGHTLY_73_END a=release DONTBUILD CLOSED TREE
```

```
./mach bootstrap
# stops at python
brew install nasm rust
cargo install cbindgen
./mach build
```
