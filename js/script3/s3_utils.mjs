// js/script3/s3_utils.mjs
import { logToDiv } from '../logger.mjs';
import { PAUSE as genericPause } from '../utils.mjs';

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => genericPause(ms);
