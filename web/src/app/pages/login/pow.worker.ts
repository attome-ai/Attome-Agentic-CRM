/// <reference lib="webworker" />

// Q20-T3: solves a proof-of-work challenge off the page's thread. The page
// posts `{ nonce, difficulty }` and receives `{ answer }` (null when none was
// found within the limit).

import { solvePow } from './pow';

addEventListener('message', ({ data }: MessageEvent<{ nonce: string; difficulty: number }>) => {
  solvePow(data.nonce, data.difficulty).then(
    answer => postMessage({ answer }),
    () => postMessage({ answer: null }),
  );
});
