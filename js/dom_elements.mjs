// js/dom_elements.mjs

const elementsCache = {};

export function getElementById(id) {
    // For modules, document is globally available.
    if (elementsCache[id] && document.body.contains(elementsCache[id])) { // Check if still in DOM
        return elementsCache[id];
    }
    const element = document.getElementById(id);
    if (element) {
        elementsCache[id] = element;
    }
    return element;
}

// Script 1
export const getOutputDivS1 = () => getElementById('output');
export const getXssTargetDiv = () => getElementById('xss-target-div');
export const getRunBtnS1 = () => getElementById('runBtnS1');

// Script 2
export const getOutputCanvasS2 = () => getElementById('output-canvas');
export const getInteractiveCanvasS2 = () => getElementById('interactive-canvas');
export const getCanvasCoordStatusS2 = () => getElementById('canvas-coord-status');
export const getRunBtnCanvasS2 = () => getElementById('runCanvasBtnS2');

// Script 3
export const getOutputAdvancedS3 = () => getElementById('output-advanced');
export const getRopGadgetsInput = () => getElementById('rop-gadgets-input');
export const getRopChainInput = () => getElementById('rop-chain-input');
export const getMemViewAddrInput = () => getElementById('mem-view-addr');
export const getMemViewSizeInput = () => getElementById('mem-view-size');
export const getRunBtnAdvancedS3 = () => getElementById('runAdvancedBtnS3');
export const getBuildRopChainBtn = () => getElementById('buildRopChainBtn');
export const getViewMemoryBtn = () => getElementById('viewMemoryBtn');


export function cacheCommonElements() {
    // Pre-cache elements if needed, called from main.mjs
    getRunBtnS1();
    getRunBtnCanvasS2();
    getRunBtnAdvancedS3();
    // Add others if frequently accessed and critical to cache
}
