import type { Config } from '@jest/types';

const config: Config.InitialOptions = {
    verbose: true,
    preset: 'ts-jest',
    testEnvironment: 'node',
    coveragePathIgnorePatterns: ['<rootDir>/node_modules/', '<rootDir>/test/'],
    coverageReporters: ['lcov'],
};

export default config;
