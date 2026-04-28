import { useEffect, useRef, useCallback } from 'react';

export function usePolling(callback: () => void, intervalSec: number) {
  const saved = useRef(callback);
  useEffect(() => { saved.current = callback; }, [callback]);

  const start = useCallback(() => {
    if (intervalSec <= 0) return;
    return setInterval(() => saved.current(), intervalSec * 1000);
  }, [intervalSec]);

  useEffect(() => {
    const id = start();
    return () => { if (id) clearInterval(id); };
  }, [start]);
}
