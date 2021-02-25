# AMD-Hypervisor
A basic Secure Virtual Machine hypervisor

This is a project in development that I have been working on since December. It's a basic hypervisor for the AMD platform, which demonstrates basic concepts such as virtualizing all cores, intercepting vmmcalls, and manipulating nested page tables. I wanted to research hypervisors beause I believe they are a powerful tool for dynamically analyzing software. 
Don't expect this to work perfectly, It is just a simple PoC that is not completely finished yet. 

## To Do list:
- fix CR3 switching
- implement MSR syscall hook

## Credits:
Tandasat - for some structures such as VMCB, and for a lot of good information in his project, Simplesvmhook
Zero-Tang - Idea of NCR3 switching
