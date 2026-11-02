import { GuardBlockError } from '../contracts/x402-types';

export interface BehaviourConfig {
  maxVelocityPerMinute?: number;
  maxConsecutive402s?: number;
}

export interface BehaviourTracker {
  recordAttempt(resource: string, intentId?: string): void;
  recordSuccess(resource: string, intentId?: string): void;
  reset(): void;
}

/**
 * L6 Behavioral Loop & Velocity Protection Layer:
 * - Detects repeated 402 challenge loops for the same resource without forward progress (LOOP_DETECTED)
 * - Limits global request velocity within a sliding 60-second window (VELOCITY)
 */
export function createBehaviourTracker(config: BehaviourConfig = {}): BehaviourTracker {
  const maxVelocity = config.maxVelocityPerMinute || 20;
  const maxLoops = config.maxConsecutive402s || 3;

  // Sliding window timestamps of attempts (ms)
  const attemptTimestamps: number[] = [];

  // Consecutive unpaid 402 challenges per resource + intent key
  const consecutiveChallengesByResource = new Map<string, number>();

  return {
    recordAttempt(resource: string, intentId?: string) {
      const now = Date.now();

      // 1. Sliding window velocity check (last 60 seconds)
      const oneMinuteAgo = now - 60_000;
      while (attemptTimestamps.length > 0 && attemptTimestamps[0] < oneMinuteAgo) {
        attemptTimestamps.shift();
      }

      if (attemptTimestamps.length >= maxVelocity) {
        throw new GuardBlockError(
          'VELOCITY',
          'L6',
          `Payment velocity limit exceeded: ${attemptTimestamps.length + 1} requests in the last 60 seconds (max: ${maxVelocity})`
        );
      }

      attemptTimestamps.push(now);

      // 2. Loop detection check for this resource & intent
      const loopKey = intentId ? `${resource}::${intentId}` : resource;
      const currentCount = (consecutiveChallengesByResource.get(loopKey) || 0) + 1;
      consecutiveChallengesByResource.set(loopKey, currentCount);

      if (currentCount > maxLoops) {
        throw new GuardBlockError(
          'LOOP_DETECTED',
          'L6',
          `Unpaid 402 loop detected: resource ${resource} requested payment ${currentCount} times consecutively without forward progress`
        );
      }
    },

    recordSuccess(resource: string, intentId?: string) {
      const loopKey = intentId ? `${resource}::${intentId}` : resource;
      consecutiveChallengesByResource.delete(loopKey);
    },

    reset() {
      attemptTimestamps.length = 0;
      consecutiveChallengesByResource.clear();
    },
  };
}
