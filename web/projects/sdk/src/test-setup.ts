// @attome/sdk has no Angular/DOM dependency, so no polyfills or TestBed
// bootstrap are needed here (contrast projects/base and projects/xrm's own
// test-setup.ts). The file still has to exist: the unit-test builder
// discovers it by convention.
export {};
