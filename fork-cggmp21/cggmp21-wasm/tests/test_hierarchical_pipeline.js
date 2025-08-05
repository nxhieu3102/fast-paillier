// test_hierarchical_pipeline.js - Main thread implementation for Hierarchical Threshold CGGMP21
import init, { 
    StatefulHierarchicalThresholdKeygenProtocol, 
    StatefulAuxGenProtocol,
    StatefulSigningProtocol
} from '../pkg/cggmp21_wasm.js';

// Test configuration for 3-of-4 hierarchical threshold with ranks [0, 0, 1, 1]
const parties = [
    {
        i: 0, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [1, 2, 3]
    },
    {
        i: 1, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 2, 3]
    },
    {
        i: 2, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 1, 3]
    },
    {
        i: 3, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 1, 2]
    }
];

const MESSAGE_TO_SIGN = "48656c6c6f2c20576f726c6421"; // "Hello, World!" in hex

// === CACHE UTILITIES ===
const CACHE_PREFIX = "htss-cache:";
const CACHE_VERSION = "v1.0"; // Bump to invalidate all old data
const CACHE_SESSION = `session-${Date.now()}`; // Optional: session-based caching

// Cache utilities that work in both main thread and web worker
const CacheManager = {
    // Check if localStorage is available
    isAvailable() {
        try {
            return typeof localStorage !== 'undefined' && localStorage !== null;
        } catch (e) {
            return false;
        }
    },

    // Generate cache key
    getKey(phase, round, config = null) {
        const configStr = config ? `-${JSON.stringify(config).replace(/[^a-zA-Z0-9]/g, '')}` : '';
        return `${CACHE_PREFIX}${CACHE_VERSION}:${phase}:${round}${configStr}`;
    },

    // Save data to cache
    save(phase, round, data, config = null) {
        if (!this.isAvailable()) {
            console.log(`Cache not available, skipping save for ${phase}:${round}`);
            return false;
        }
        
        try {
            const key = this.getKey(phase, round, config);
            const cacheData = {
                timestamp: Date.now(),
                phase,
                round,
                config,
                data: JSON.parse(JSON.stringify(data)) // Deep clone to avoid references
            };
            
            localStorage.setItem(key, JSON.stringify(cacheData));
            console.log(`✅ Cached ${phase}:${round} (${(JSON.stringify(cacheData).length / 1024).toFixed(1)}KB)`);
            return true;
        } catch (error) {
            console.warn(`Failed to cache ${phase}:${round}:`, error.message);
            return false;
        }
    },

    // Load data from cache
    load(phase, round, config = null) {
        if (!this.isAvailable()) {
            console.log(`Cache not available, skipping load for ${phase}:${round}`);
            return null;
        }
        
        try {
            const key = this.getKey(phase, round, config);
            const cached = localStorage.getItem(key);
            
            if (!cached) {
                console.log(`💾 No cache found for ${phase}:${round}`);
                return null;
            }
            
            const cacheData = JSON.parse(cached);
            const age = Date.now() - cacheData.timestamp;
            const ageMinutes = (age / 60000).toFixed(1);
            
            console.log(`🔄 Loading cached ${phase}:${round} (${ageMinutes}min old, ${(cached.length / 1024).toFixed(1)}KB)`);
            return cacheData.data;
        } catch (error) {
            console.warn(`Failed to load cache for ${phase}:${round}:`, error.message);
            return null;
        }
    },

    // Check if cache exists
    exists(phase, round, config = null) {
        if (!this.isAvailable()) return false;
        const key = this.getKey(phase, round, config);
        return localStorage.getItem(key) !== null;
    },

    // Clear specific cache
    clear(phase, round = null, config = null) {
        if (!this.isAvailable()) return 0;
        
        let cleared = 0;
        const keys = Object.keys(localStorage);
        
        for (const key of keys) {
            if (key.startsWith(CACHE_PREFIX + CACHE_VERSION)) {
                const shouldClear = round 
                    ? key === this.getKey(phase, round, config)
                    : key.includes(`:${phase}:`);
                
                if (shouldClear) {
                    localStorage.removeItem(key);
                    cleared++;
                }
            }
        }
        
        console.log(`🗑️ Cleared ${cleared} cache entries for ${phase}${round ? `:${round}` : ''}`);
        return cleared;
    },

    // Clear all cache
    clearAll() {
        if (!this.isAvailable()) return 0;
        
        let cleared = 0;
        const keys = Object.keys(localStorage);
        
        for (const key of keys) {
            if (key.startsWith(CACHE_PREFIX)) {
                localStorage.removeItem(key);
                cleared++;
            }
        }
        
        console.log(`🗑️ Cleared all ${cleared} cache entries`);
        return cleared;
    },

    // List all cached items
    list() {
        if (!this.isAvailable()) return [];
        
        const items = [];
        const keys = Object.keys(localStorage);
        
        for (const key of keys) {
            if (key.startsWith(CACHE_PREFIX + CACHE_VERSION)) {
                try {
                    const data = JSON.parse(localStorage.getItem(key));
                    const size = localStorage.getItem(key).length;
                    const age = Date.now() - data.timestamp;
                    
                    items.push({
                        key,
                        phase: data.phase,
                        round: data.round,
                        config: data.config,
                        size: (size / 1024).toFixed(1) + 'KB',
                        age: (age / 60000).toFixed(1) + 'min',
                        timestamp: new Date(data.timestamp).toLocaleString()
                    });
                } catch (e) {
                    // Skip invalid cache entries
                }
            }
        }
        
        return items.sort((a, b) => a.phase.localeCompare(b.phase));
    },

    // Get cache statistics
    getStats() {
        const items = this.list();
        const totalSize = items.reduce((sum, item) => sum + parseFloat(item.size), 0);
        
        return {
            count: items.length,
            totalSize: totalSize.toFixed(1) + 'KB',
            phases: [...new Set(items.map(item => item.phase))],
            available: this.isAvailable()
        };
    }
};

// Helper function to use cache with fallback
async function withCache(phase, round, computeFn, config = null, forceRecompute = false) {
    const cacheKey = { phase, round, config };
    
    // Try to load from cache first (unless forced to recompute)
    if (!forceRecompute) {
        const cached = CacheManager.load(phase, round, config);
        if (cached !== null) {
            log(`🔄 Using cached data for ${phase}:${round}`, "round");
            return cached;
        }
    }
    
    // Compute fresh data
    log(`⚡ Computing fresh data for ${phase}:${round}`, "round");
    const result = await computeFn();
    
    // Cache the result
    CacheManager.save(phase, round, result, config);
    
    return result;
}

// Global state for WASM initialization
let wasmInitialized = false;

// Web Worker Manager for heavy computations
class HierarchicalWorkerManager {
    constructor() {
        this.worker = null;
        this.messageId = 0;
        this.pendingMessages = new Map();
        this.progressCallback = null;
        this.isWorkerSupported = typeof Worker !== 'undefined';
    }

    async initialize() {
        if (!this.isWorkerSupported) {
            console.log("Web Workers not supported, falling back to main thread");
            return;
        }

        try {
            console.log('🔧 Creating new Hierarchical Signing Worker...');
            this.worker = new Worker('./test_hierarchical_worker.js', { type: 'module' });
            this.worker.onmessage = this.handleWorkerMessage.bind(this);
            this.worker.onerror = this.handleWorkerError.bind(this);
            
            // Initialize worker
            console.log('📤 Sending init message to hierarchical worker...');
            await this.sendMessage('init');
            console.log('✅ Hierarchical Worker initialization completed');
            log("🔧 Hierarchical Web Worker initialized successfully", "success");
        } catch (error) {
            console.warn("Failed to initialize Hierarchical Web Worker, falling back to main thread:", error);
            this.worker = null;
        }
    }

    handleWorkerMessage(e) {
        const { type, data, messageId } = e.data;
        
        console.log('🔄 Hierarchical Worker message received:', { type, messageId, hasData: !!data });
        
        if (type === 'progress') {
            console.log('🔍 Progress message received, callback exists:', !!this.progressCallback);
            if (this.progressCallback) {
                console.log('📊 Calling progress callback with:', data);
                this.progressCallback(data);
            } else {
                console.warn('⚠️ Progress callback not set yet, message data:', data);
            }
            return;
        }

        if (messageId && this.pendingMessages.has(messageId)) {
            const { resolve, reject } = this.pendingMessages.get(messageId);
            this.pendingMessages.delete(messageId);
            
            if (type === 'error') {
                reject(new Error(data.message));
            } else {
                resolve(data);
            }
        } else if (messageId) {
            console.warn('⚠️ Received message with unknown messageId:', messageId);
        }
    }

    handleWorkerError(error) {
        log(`Hierarchical Worker error: ${error.message}`, "error");
        // Reject all pending messages
        for (const { reject } of this.pendingMessages.values()) {
            reject(new Error('Hierarchical Worker error: ' + error.message));
        }
        this.pendingMessages.clear();
    }

    async sendMessage(type, data = null) {
        if (!this.worker) {
            throw new Error("Hierarchical Worker not available");
        }

        const messageId = ++this.messageId;
        
        return new Promise((resolve, reject) => {
            this.pendingMessages.set(messageId, { resolve, reject });
            this.worker.postMessage({ type, data, messageId });
        });
    }

    setProgressCallback(callback) {
        console.log('🔧 Setting hierarchical progress callback:', !!callback);
        this.progressCallback = callback;
    }

    terminate() {
        if (this.worker) {
            this.worker.terminate();
            this.worker = null;
        }
        this.pendingMessages.clear();
    }
}

// Global hierarchical worker manager instance
const hierarchicalWorkerManager = new HierarchicalWorkerManager();

// Browser-specific logging function
function log(message, type = "normal") {
    console.log("📝 log called:", message, type);
    const timestamp = new Date().toLocaleTimeString();
    let formattedMessage = `[${timestamp}] ${message}`;
    
    // Format message based on type
    if (type === "success") {
        formattedMessage = `[${timestamp}] ✅ ${message}`;
    } else if (type === "error") {
        formattedMessage = `[${timestamp}] ❌ ${message}`;
    } else if (type === "phase") {
        formattedMessage = `\n[${timestamp}] 🔄 ${message}\n${'='.repeat(60)}`;
    } else if (type === "round") {
        formattedMessage = `[${timestamp}] 📍 ${message}`;
    }

    // Log to console
    console.log(formattedMessage);
    
    // If in browser environment, also log to DOM
    if (typeof document !== 'undefined') {
        const output = document.getElementById('output');
        console.log('🎯 DOM output element found:', !!output);
        if (output) {
            output.textContent += formattedMessage + '\n';
            output.scrollTop = output.scrollHeight;
            console.log('✅ Added to DOM output');
        } else {
            console.warn('⚠️ DOM output element not found');
        }
    } else {
        console.log('🌐 Not in browser environment');
    }
}

// Progress bar management
function updateProgressBar(phase, progress, message) {
    console.log('📊 updateProgressBar called:', { phase, progress, message });
    
    if (typeof document === 'undefined') {
        console.log('🌐 Not in browser environment');
        return;
    }
    
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const phaseText = document.getElementById('phaseText');
    
    console.log('🎯 Progress elements found:', {
        progressBar: !!progressBar,
        progressText: !!progressText,
        phaseText: !!phaseText
    });
    
    if (progressBar && progressText && phaseText) {
        if (progress !== null) {
            progressBar.style.width = `${progress}%`;
            progressText.textContent = `${Math.round(progress)}%`;
            console.log(`📈 Progress bar updated to ${progress}%`);
        }
        phaseText.textContent = `${phase}: ${message}`;
        console.log(`📝 Phase text updated: ${phase}: ${message}`);
        
        // Change color based on progress
        if (progress >= 100) {
            progressBar.style.backgroundColor = '#28a745'; // Success green
        } else if (progress >= 75) {
            progressBar.style.backgroundColor = '#17a2b8'; // Info blue
        } else if (progress >= 50) {
            progressBar.style.backgroundColor = '#ffc107'; // Warning yellow
        } else {
            progressBar.style.backgroundColor = '#6c757d'; // Secondary gray
        }
    } else {
        console.warn('⚠️ Some progress elements not found');
    }
}

// Initialize WASM module
async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        wasmInitialized = true;
        log("WASM module initialized successfully", "success");
    }
}

// Helper functions for message routing (fallback for main thread)
const createRecipientMap = (items, partyConfig) => {
    const map = {};
    items.forEach((item, idx) => {
        map[idx] = items.filter((_, idx2) => partyConfig[idx].ids.includes(idx2));
    });
    return map;
};

const createUnicastMap = (unicastMessages, partyConfig) => {
    const map = {};
    
    // Initialize map with empty arrays for each party
    partyConfig.forEach((_, idx) => {
        map[idx] = [];
    });
    
    // Route unicast messages to recipients
    unicastMessages.forEach((partyMessages, senderIdx) => {
        if (Array.isArray(partyMessages)) {
            console.log(`Processing ${partyMessages.length} unicast messages from party ${senderIdx}`);
            partyMessages.forEach((unicastMsg, msgIdx) => {
                const recipientIdx = Array.isArray(unicastMsg) ? unicastMsg[0] : unicastMsg.recipient;
                const message = Array.isArray(unicastMsg) ? unicastMsg[1] : unicastMsg.msg;
                
                console.log(`Message ${msgIdx}: sender=${senderIdx}, recipient=${recipientIdx}`);
                
                if (map[recipientIdx] !== undefined) {
                    map[recipientIdx].push(message);
                } else {
                    console.warn(`Invalid recipient index ${recipientIdx} for message from party ${senderIdx}`);
                }
            });
        }
    });
    
    return map;
};

const createP2PMap = (p2pMessages, parties) => {
    const map = {};
    
    // Initialize map with empty arrays for each party
    parties.forEach((_, idx) => {
        map[idx] = [];
    });
    
    // Route P2P messages to recipients
    p2pMessages.forEach((partyMessages, senderIdx) => {
        partyMessages.forEach(p2pMsg => {
            map[p2pMsg.recipient].push(p2pMsg.message);
        });
    });
    
    return map;
};

// Worker-based functions (with fallback to main thread)
async function runHierarchicalKeyGeneration() {
    if (hierarchicalWorkerManager.worker) {
        log("🔧 Running hierarchical key generation in Web Worker", "phase");
        return await hierarchicalWorkerManager.sendMessage('run_hierarchical_keygen');
    } else {
        return await runHierarchicalKeyGenerationMainThread();
    }
}

async function runHierarchicalAuxGeneration(incompleteKeyShares) {
    if (hierarchicalWorkerManager.worker) {
        log("🔧 Running hierarchical aux generation in Web Worker", "phase");
        return await hierarchicalWorkerManager.sendMessage('run_hierarchical_auxgen', { incompleteKeyShares });
    } else {
        return await runHierarchicalAuxGenerationMainThread(incompleteKeyShares);
    }
}

async function runHierarchicalSigning(completeKeyShares) {
    if (hierarchicalWorkerManager.worker) {
        log("🔧 Running hierarchical signing in Web Worker", "phase");
        return await hierarchicalWorkerManager.sendMessage('run_hierarchical_signing', { completeKeyShares });
    } else {
        return await runHierarchicalSigningMainThread(completeKeyShares);
    }
}

async function runFullHierarchicalPipelineTest() {
    console.log('🚀 runFullHierarchicalPipelineTest called');
    console.log('Worker exists:', !!hierarchicalWorkerManager.worker);
    console.log('Progress callback exists:', !!hierarchicalWorkerManager.progressCallback);
    
    if (hierarchicalWorkerManager.worker) {
        log("🔧 Running full hierarchical pipeline in Web Worker", "phase");
        return await hierarchicalWorkerManager.sendMessage('run_hierarchical_pipeline');
    } else {
        log("🔧 Running full hierarchical pipeline in main thread (fallback)", "phase");
        return await runFullHierarchicalPipelineTestMainThread();
    }
}

// Validate configuration
async function validateHierarchicalConfiguration() {
    if (hierarchicalWorkerManager.worker) {
        return await hierarchicalWorkerManager.sendMessage('validate_hierarchical_config');
    } else {
        return validateConfigurationMainThread();
    }
}

// Fallback implementations for main thread
function validateConfigurationMainThread() {
    console.log("Validating hierarchical threshold configuration...");
    
    const n = parties.length;
    const t = parties[0].t;
    const ranks = parties[0].ranks;
    
    // Basic validation
    if (t > n) {
        throw new Error(`Invalid threshold: t=${t} > n=${n}`);
    }
    
    if (ranks.length !== n) {
        throw new Error(`Ranks array length (${ranks.length}) doesn't match number of parties (${n})`);
    }
    
    // Validate rank constraints
    for (let i = 0; i < ranks.length; i++) {
        if (ranks[i] >= t) {
            throw new Error(`Invalid rank: party ${i} has rank ${ranks[i]} >= threshold ${t}`);
        }
    }
    
    // Check for valid authorized sets
    let validSets = 0;
    
    for (let mask = 0; mask < (1 << n); mask++) {
        const selectedParties = [];
        for (let i = 0; i < n; i++) {
            if (mask & (1 << i)) {
                selectedParties.push(i);
            }
        }
        
        if (selectedParties.length === t) {
            const selectedRanks = selectedParties.map(i => ranks[i]).sort((a, b) => a - b);
            let isValid = true;
            for (let j = 0; j < t; j++) {
                if (selectedRanks[j] > j) {
                    isValid = false;
                    break;
                }
            }
            if (isValid) {
                validSets++;
                console.log(`Valid authorized set: {${selectedParties.join(',')}} with ranks [${selectedRanks.join(',')}]`);
            }
        }
    }
    
    if (validSets === 0) {
        throw new Error("No valid authorized sets found for the given rank configuration");
    }
    
    console.log(`Configuration validated: t=${t}, n=${n}, valid authorized sets=${validSets}`);
    console.log(`Rank distribution: ${ranks.map((r, i) => `Party${i}:${r}`).join(', ')}`);
    
    return { t, n, ranks, validSets };
}

async function runHierarchicalKeyGenerationMainThread() {
    log("Starting Hierarchical Threshold Key Generation Phase", "phase");
    
    // Validate configuration first
    const validationResult = validateConfigurationMainThread();
    log(`Configuration validated: ${validationResult.validSets} valid authorized sets`, "round");

    // Check if we have complete cached results
    const completeCache = CacheManager.load('keygen', 'complete', validationResult);
    if (completeCache) {
        log("🔄 Using complete cached keygen results", "success");
        return completeCache;
    }

    const keygenProtocols = [];
    for (let i = 0; i < parties.length; i++) {
        const party = { ...parties[i] };
        try {
            log(`Initializing hierarchical protocol for party ${i} (rank: ${party.ranks[i]})...`, "round");
            const protocol = new StatefulHierarchicalThresholdKeygenProtocol(party);
            keygenProtocols.push(protocol);
            log(`Party ${i} hierarchical protocol initialized successfully`, "round");
        } catch (error) {
            log(`Failed to create hierarchical protocol for party ${i}: ${error.message}`, "error");
            throw error;
        }
    }
    
    // Round 1: Generate commitments (with caching)
    const commitments = await withCache('keygen', 'round1-commitments', async () => {
        log("Round 1: Generating commitments...", "round");
        return keygenProtocols.map((protocol, idx) => {
            try {
                const commitment = protocol.round1_generate_commitment();
                console.log(`Party ${idx} (rank ${parties[idx].ranks[idx]}) generated commitment successfully`);
                return commitment;
            } catch (error) {
                console.error(`Party ${idx} failed in round 1: ${error.message}`);
                throw error;
            }
        });
    }, validationResult);
    
    log("Setting commitments for all parties...", "round");
    const commitmentsMap = createRecipientMap(commitments, parties);
    keygenProtocols.forEach((protocol, idx) => {
        try {
            protocol.set_round1_commitments({
                commitments: commitmentsMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${commitmentsMap[idx].length} round 1 commitments`);
        } catch (error) {
            console.error(`Party ${idx} failed setting round 1 commitments: ${error.message}`);
            throw error;
        }
    });
    
    // Create reliability checks (with caching)
    const reliabilityChecks = await withCache('keygen', 'reliability-checks', async () => {
        log("Creating reliability checks...", "round");
        return keygenProtocols.map((protocol, idx) => {
            try {
                if (parties[idx].reliable_broadcast_enforced) {
                    const reliabilityCheck = protocol.create_reliability_check();
                    console.log(`Party ${idx} created reliability check`);
                    return reliabilityCheck;
                } else {
                    console.log(`Party ${idx} skipping reliability check (not enforced)`);
                    return null;
                }
            } catch (error) {
                console.error(`Party ${idx} failed creating reliability check: ${error.message}`);
                throw error;
            }
        });
    }, validationResult);
    
    // Round 2: Generate decommitments and shares (with caching)
    const { decommitments, unicastMessages } = await withCache('keygen', 'round2-data', async () => {
        log("Round 2: Generating decommitments and shares...", "round");
        
        const decommitments = keygenProtocols.map((protocol, idx) => {
            try {
                const decommitment = protocol.round2_get_decommitment();
                console.log(`Party ${idx} generated decommitment successfully`);
                return decommitment;
            } catch (error) {
                console.error(`Party ${idx} failed getting round 2 decommitment: ${error.message}`);
                throw error;
            }
        });
        
        const unicastMessages = keygenProtocols.map((protocol, idx) => {
            try {
                const messages = protocol.round2_get_unicast_messages();
                console.log(`Party ${idx} generated ${messages.length} unicast messages`);
                return messages;
            } catch (error) {
                console.error(`Party ${idx} failed getting round 2 unicast messages: ${error.message}`);
                throw error;
            }
        });

        return { decommitments, unicastMessages };
    }, validationResult);
    
    log("Setting decommitments and sigma shares...", "round");
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    const sigmasMap = createUnicastMap(unicastMessages, parties);
    
    keygenProtocols.forEach((protocol, idx) => {
        try {
            protocol.set_round2_decommitments({
                decommitments: decommitmentsMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${decommitmentsMap[idx].length} round 2 decommitments`);
            
            protocol.set_round2_sigmas({
                sigmas: sigmasMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${sigmasMap[idx].length} round 2 sigma shares`);
        } catch (error) {
            console.error(`Party ${idx} failed setting round 2 data: ${error.message}`);
            throw error;
        }
    });
    
    log("Validating round 2 data...", "round");
    keygenProtocols.forEach((protocol, idx) => {
        try {
            protocol.validate_round2_and_prepare_round3();
            console.log(`Party ${idx} validated round 2 data successfully`);
        } catch (error) {
            console.error(`Party ${idx} failed validating round 2 data: ${error.message}`);
            throw error;
        }
    });
    
    // Round 3: Generate Schnorr proofs (with caching)
    const schnorrProofs = await withCache('keygen', 'round3-proofs', async () => {
        log("Round 3: Generating Schnorr proofs...", "round");
        return keygenProtocols.map((protocol, idx) => {
            try {
                const proof = protocol.round3_generate_proof();
                console.log(`Party ${idx} generated Schnorr proof successfully`);
                return proof;
            } catch (error) {
                console.error(`Party ${idx} failed generating round 3 proof: ${error.message}`);
                throw error;
            }
        });
    }, validationResult);
    
    log("Setting Schnorr proofs...", "round");
    const proofsMap = createRecipientMap(schnorrProofs, parties);
    keygenProtocols.forEach((protocol, idx) => {
        try {
            protocol.set_round3_schnorr_proofs({
                sch_proof: proofsMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${proofsMap[idx].length} round 3 Schnorr proofs`);
        } catch (error) {
            console.error(`Party ${idx} failed setting round 3 proofs: ${error.message}`);
            throw error;
        }
    });
    
    // Final: Generate key shares (with caching)
    const incompleteKeyShares = await withCache('keygen', 'final-shares', async () => {
        log("Final: Generating hierarchical threshold key shares...", "round");
        return keygenProtocols.map((protocol, idx) => {
            try {
                const keyShare = protocol.finalize_key_generation();
                console.log(`Party ${idx} generated hierarchical threshold key share successfully`);
                return keyShare;
            } catch (error) {
                console.error(`Party ${idx} failed finalizing key generation: ${error.message}`);
                throw error;
            }
        });
    }, validationResult);
    
    // Validate key shares
    console.log("Validating generated hierarchical key shares...");
    incompleteKeyShares.forEach((keyShare, idx) => {
        if (keyShare && typeof keyShare === 'object') {
            console.log(`Party ${idx}: Hierarchical key share generated with rank ${parties[idx].ranks[idx]}`);
        } else {
            throw new Error(`Invalid hierarchical key share for party ${idx}`);
        }
    });
    
    log(`Hierarchical threshold key generation completed! Generated ${incompleteKeyShares.length} incomplete key shares`, "success");
    
    const result = {
        incompleteKeyShares,
        validationResult,
        commitments,
        reliabilityChecks,
        decommitments,
        unicastMessages,
        schnorrProofs
    };

    // Cache the complete result
    CacheManager.save('keygen', 'complete', result, validationResult);
    
    return result;
}

async function runHierarchicalAuxGenerationMainThread(incompleteKeyShares) {
    log("Starting Auxiliary Generation Phase", "phase");
    
    // Check for complete cached result
    const completeCache = CacheManager.load('auxgen', 'complete');
    if (completeCache) {
        log("🔄 Using complete cached auxgen results", "success");
        return completeCache;
    }
    
    const auxGenProtocols = await Promise.all(
        parties.map(async (party, idx) => {
            try {
                console.log(`Initializing auxiliary generation protocol for party ${idx}...`);
                const protocol = await new StatefulAuxGenProtocol({
                    ...party,
                    sid: party.sid + "-auxgen",
                    compute_multiexp_table: false,
                    compute_crt: false
                });
                console.log(`Party ${idx} auxiliary generation protocol initialized successfully`);
                return protocol;
            } catch (error) {
                console.error(`Failed to create auxiliary generation protocol for party ${idx}: ${error.message}`);
                throw error;
            }
        })
    );
    
    // Round 1: Generate commitments (with caching)
    const commitments = await withCache('auxgen', 'round1-commitments', async () => {
        log("Round 1: Generating commitments...", "round");
        return auxGenProtocols.map((protocol, idx) => {
            try {
                const commitment = protocol.round1_generate_commitment();
                console.log(`Party ${idx} generated auxiliary commitment successfully`);
                return commitment;
            } catch (error) {
                console.error(`Party ${idx} failed generating auxiliary commitment: ${error.message}`);
                throw error;
            }
        });
    });

    const commitmentsMap = createRecipientMap(commitments, parties);
    auxGenProtocols.forEach((protocol, idx) => {
        try {
            protocol.set_round1_commitments({
                commitments: commitmentsMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${commitmentsMap[idx].length} auxiliary round 1 commitments`);
        } catch (error) {
            console.error(`Party ${idx} failed setting auxiliary round 1 commitments: ${error.message}`);
            throw error;
        }
    });
    
    // Round 2: Get decommitments (with caching)
    const decommitments = await withCache('auxgen', 'round2-decommitments', async () => {
        log("Round 2: Getting decommitments...", "round");
        return auxGenProtocols.map((protocol, idx) => {
            try {
                const decommitment = protocol.round2_get_decommitment();
                console.log(`Party ${idx} generated auxiliary decommitment successfully`);
                return decommitment;
            } catch (error) {
                console.error(`Party ${idx} failed getting auxiliary decommitment: ${error.message}`);
                throw error;
            }
        });
    });
    
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    auxGenProtocols.forEach((protocol, idx) => {
        try {
            protocol.set_round2_decommitments({
                decommitments: decommitmentsMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${decommitmentsMap[idx].length} auxiliary round 2 decommitments`);
            
            protocol.validate_round2_decommitments();
            console.log(`Party ${idx} validated auxiliary round 2 decommitments`);
        } catch (error) {
            console.error(`Party ${idx} failed with auxiliary round 2 decommitments: ${error.message}`);
            throw error;
        }
    });
    
    // Round 3: Create messages (with caching)
    const round3Messages = await withCache('auxgen', 'round3-messages', async () => {
        log("Round 3: Creating messages...", "round");
        return auxGenProtocols.map((protocol, idx) => {
            try {
                const messages = protocol.round3_create_messages();
                console.log(`Party ${idx} created auxiliary round 3 messages successfully`);
                return messages;
            } catch (error) {
                console.error(`Party ${idx} failed creating auxiliary round 3 messages: ${error.message}`);
                throw error;
            }
        });
    });
    
    log("Final: Finalizing auxiliary info...", "round");
    auxGenProtocols.forEach((protocol, idx) => {
        try {
            // Collect messages intended for this party from all other parties
            const messagesForParty = [];

            round3Messages.forEach((msgs, senderIdx) => {
                if (senderIdx !== idx && parties[idx].ids.includes(senderIdx)) {
                    if (Array.isArray(msgs)) {
                        msgs.forEach(msgPair => {
                            if (Array.isArray(msgPair) && msgPair.length === 2) {
                                const [recipientId, message] = msgPair;
                                if (recipientId === idx) {
                                    messagesForParty.push(message);
                                }
                            }
                        });
                    }
                }
            });

            protocol.set_round3_messages({
                messages: messagesForParty,
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${messagesForParty.length} auxiliary round 3 messages`);
        } catch (error) {
            console.error(`Party ${idx} failed setting auxiliary round 3 messages: ${error.message}`);
            throw error;
        }
    });
    
    const auxInfos = auxGenProtocols.map((protocol, idx) => {
        try {
            const auxInfo = protocol.finalize();
            console.log(`Party ${idx} finalized auxiliary information successfully`);
            return auxInfo;
        } catch (error) {
            console.error(`Party ${idx} failed finalizing auxiliary information: ${error.message}`);
            throw error;
        }
    });
    
    const completeKeyShares = incompleteKeyShares.map((incompleteShare, idx) => {
        return {
            core: incompleteShare,
            aux: auxInfos[idx],
            party_index: idx,
            rank: parties[idx].ranks[idx]
        };
    });
    
    log(`Auxiliary generation completed! Generated ${completeKeyShares.length} complete key shares`, "success");
    
    const result = {
        completeKeyShares,
        auxInfos,
        round3Messages
    };

    // Cache the complete result
    CacheManager.save('auxgen', 'complete', result);
    
    return result;
}

// Phase 3: Hierarchical Threshold Signing (Main Thread Implementation)
async function runHierarchicalSigningMainThread(completeKeyShares) {
    log("Starting Hierarchical Threshold Signing Phase", "phase");
    log(`Precompute tables: DISABLED (as requested)`, "phase");
    
    // Check for complete cached result
    const completeCache = CacheManager.load('signing', 'complete');
    if (completeCache) {
        log("🔄 Using complete cached signing results", "success");
        return completeCache;
    }
    
    // Use configuration: n=4, t=3, ranks=[0,0,1,1], signers=[0,1,2] (parties with ranks [0,0,1])
    const signingParties = [0, 1, 2]; // Party indices that will participate in signing
    const signingKeyShares = signingParties.map(idx => completeKeyShares[idx]);
    
    // Validate signing configuration according to hierarchical rules
    // For valid signing set: if ranks are sorted as r1 ≤ r2 ≤ ... ≤ rt, then ri ≤ i-1 for all i
    const signerRanks = signingParties.map(idx => parties[idx].ranks[idx]).sort((a, b) => a - b);
    const isValidSigningSet = signerRanks.every((rank, idx) => rank <= idx);
    
    log(`Signing parties: [${signingParties.join(', ')}] with ranks [${signerRanks.join(', ')}]`, "round");
    log(`Valid signing set: ${isValidSigningSet ? 'YES' : 'NO'}`, "round");
    
    if (!isValidSigningSet) {
        throw new Error(`Invalid signing set: ranks [${signerRanks.join(', ')}] violate hierarchical constraints`);
    }

    // Create hierarchical signing protocols (no precompute tables as requested)
    const signingProtocols = signingParties.map((globalIdx, localIdx) => {
        const protocol = new StatefulSigningProtocol({
            i: localIdx,
            signing_parties: [0, 1, 2], // Local indices in signing group
            sid: parties[globalIdx].sid + "-signing",
            reliable_broadcast_enforced: false,
            message_hex: MESSAGE_TO_SIGN,
            enable_precomputable: false // Disable precompute tables as requested
        }, signingKeyShares[localIdx]);
        
        return protocol;
    });

    // Round 1a: Generate broadcast messages (with caching)
    const { round1aMessages, end1a, start1a } = await withCache('signing', 'round1a-messages', async () => {
        log("Round 1a: Generating broadcast messages...", "round");
        const start1a = performance.now();
        const round1aMessages = signingProtocols.map(protocol => 
            protocol.round1a_generate_message()
        );
        const end1a = performance.now();
        log(`Round 1a completed in ${(end1a - start1a).toFixed(2)}ms`, "round");
        return { round1aMessages, end1a, start1a };
    });

    signingProtocols.forEach((protocol, idx) => {
        const otherMessages = round1aMessages.filter((_, msgIdx) => msgIdx !== idx);
        const otherIds = signingParties.filter((_, partyIdx) => partyIdx !== idx);
        protocol.set_round1a_messages({
            messages: otherMessages,
            ids: otherIds
        });
    });

    // Round 1b: Generate P2P messages (with caching)
    const round1bMessages = await withCache('signing', 'round1b-messages', async () => {
        log("Round 1b: Generating P2P messages...", "round");
        return signingProtocols.map(protocol => 
            protocol.round1b_generate_messages()
        );
    });

    const round1bMap = createP2PMap(round1bMessages, signingParties);
    signingProtocols.forEach((protocol, idx) => {
        protocol.set_round1b_messages({
            messages: round1bMap[idx],
            ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
        });
        protocol.validate_round1b_proofs();
    });

    // Round 2: Generate P2P messages (with caching)
    const { round2Messages, end2, start2 } = await withCache('signing', 'round2-messages', async () => {
        log("Round 2: Generating P2P messages...", "round");
        const start2 = performance.now();
        const round2Messages = signingProtocols.map(protocol => 
            protocol.round2_generate_messages()
        );
        const end2 = performance.now();
        log(`Round 2 completed in ${(end2 - start2).toFixed(2)}ms`, "round");
        return { round2Messages, end2, start2 };
    });

    const round2Map = createP2PMap(round2Messages, signingParties);
    signingProtocols.forEach((protocol, idx) => {
        protocol.set_round2_messages({
            messages: round2Map[idx],
            ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
        });
    });

    // Round 3: Generate P2P messages (with caching)
    const round3Messages = await withCache('signing', 'round3-messages', async () => {
        log("Round 3: Generating P2P messages...", "round");
        return signingProtocols.map(protocol => 
            protocol.round3_generate_messages()
        );
    });

    const round3Map = createP2PMap(round3Messages, signingParties);
    signingProtocols.forEach((protocol, idx) => {
        protocol.set_round3_messages({
            messages: round3Map[idx],
            ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
        });
    });

    // Generate presignatures (with caching)
    const presignatures = await withCache('signing', 'presignatures', async () => {
        log("Generating presignatures...", "round");
        return signingProtocols.map(protocol => 
            protocol.generate_presignature()
        );
    });

    // Round 4: Generate partial signatures (with caching)
    const round4Messages = await withCache('signing', 'round4-messages', async () => {
        log("Round 4: Generating partial signatures...", "round");
        return signingProtocols.map(protocol => 
            protocol.round4_generate_message()
        );
    });

    const round4Map = createRecipientMap(
        round4Messages.map(msg => (msg !== undefined && msg !== null) ? msg : {}), 
        signingParties.map((_, idx) => ({ ids: signingParties.filter((_, partyIdx) => partyIdx !== idx) }))
    );

    signingProtocols.forEach((protocol, idx) => {
        if (round4Map[idx] && round4Map[idx].length > 0) {
            protocol.set_round4_messages({
                messages: round4Map[idx],
                ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
            });
        }
    });

    // Generate final signatures (with caching)
    const signatures = await withCache('signing', 'final-signatures', async () => {
        log("Final: Generating signatures...", "round");
        return signingProtocols.map((protocol, idx) => {
            const round4Msg = round4Messages[idx];
            if (round4Msg !== undefined && round4Msg !== null) {
                return protocol.generate_signature(round4Msg);
            }
            return null;
        });
    });

    const validSignatures = signatures.filter(sig => sig !== null);
    
    // Verify signatures
    log("Verifying signatures...", "round");
    const verificationResults = [];
    
    if (validSignatures.length > 0) {
        try {
            // Get public key from the first complete key share
            const publicKeyHex = StatefulSigningProtocol.get_public_key_from_keyshare(completeKeyShares[0]);
            log(`Using public key: ${publicKeyHex}`, "round");
            
            for (let i = 0; i < validSignatures.length; i++) {
                const signature = validSignatures[i];
                const isValid = StatefulSigningProtocol.verify_signature(signature, publicKeyHex, MESSAGE_TO_SIGN);
                verificationResults.push({
                    signatureIndex: i,
                    isValid: isValid,
                    signature: signature
                });
                
                if (isValid) {
                    log(`✅ Hierarchical signature ${i} verification: VALID`, "success");
                } else {
                    log(`❌ Hierarchical signature ${i} verification: INVALID`, "error");
                }
            }
            
            const validCount = verificationResults.filter(r => r.isValid).length;
            log(`Verification complete: ${validCount}/${verificationResults.length} signatures are valid`, "success");
            
        } catch (error) {
            log(`Error during signature verification: ${error.message}`, "error");
            verificationResults.push({
                error: error.message || error
            });
        }
    }
    
    log(`Hierarchical signing completed! Generated ${validSignatures.length} signatures`, "success");
    
    // Performance summary
    const totalSigningTime = (end2 - start1a);
    log(`📊 Hierarchical Signing Performance Summary:`, "success");
    log(`- Round 1a time: ${(end1a - start1a).toFixed(2)}ms`, "success");
    log(`- Round 2 time: ${(end2 - start2).toFixed(2)}ms`, "success");
    log(`- Total signing time: ${totalSigningTime.toFixed(2)}ms`, "success");
    log(`- Precompute tables: DISABLED (as requested)`, "success");
    log(`- Signing parties: [${signingParties.join(', ')}] with ranks [${signerRanks.join(', ')}]`, "success");
    
    const result = {
        presignatures,
        signatures: validSignatures,
        verificationResults,
        performanceMetrics: {
            round1aTime: end1a - start1a,
            round2Time: end2 - start2,
            totalSigningTime,
            precomputeTablesEnabled: false,
            signingParties,
            signerRanks
        }
    };

    // Cache the complete result
    CacheManager.save('signing', 'complete', result);
    
    return result;
}

async function runFullHierarchicalPipelineTestMainThread() {
    try {
        await initializeWasm();

        log("🚀 Starting Full Hierarchical CGGMP21 Pipeline Test", "phase");
        log(`Configuration: ${parties[0].t}-of-${parties[0].n} hierarchical threshold with ranks [${parties[0].ranks.join(',')}]`);
        log(`Valid signers for rank constraint [0,0,1]: parties {0,1,2} with ranks [0,0,1]`);
        
        const incompleteKeyShares = await runHierarchicalKeyGenerationMainThread();
        const auxGenResults = await runHierarchicalAuxGenerationMainThread(incompleteKeyShares.incompleteKeyShares);
        const signingResults = await runHierarchicalSigningMainThread(auxGenResults.completeKeyShares);
        
        log("🎉 Full Hierarchical Pipeline Test Completed Successfully!", "success");
        log(`Results Summary:`, "success");
        log(`- Incomplete key shares: ${incompleteKeyShares.incompleteKeyShares.length}`, "success");
        log(`- Complete key shares: ${auxGenResults.completeKeyShares.length}`, "success");
        log(`- Presignatures: ${signingResults.presignatures.length}`, "success");
        log(`- Final signatures: ${signingResults.signatures.length}`, "success");
        log(`- Configuration: ${incompleteKeyShares.validationResult.t}-of-${incompleteKeyShares.validationResult.n} with ${incompleteKeyShares.validationResult.validSets} valid authorized sets`, "success");
        
        // Log verification results
        if (signingResults.verificationResults && signingResults.verificationResults.length > 0) {
            const validCount = signingResults.verificationResults.filter(r => r.isValid).length;
            const totalCount = signingResults.verificationResults.filter(r => !r.error).length;
            log(`- Signature verification: ${validCount}/${totalCount} signatures verified as VALID`, validCount === totalCount ? "success" : "error");
            
            if (validCount === totalCount && totalCount > 0) {
                log("🔐 All hierarchical signatures passed cryptographic verification!", "success");
            } else if (validCount > 0) {
                log("⚠️ Some hierarchical signatures failed verification - check implementation", "error");
            } else {
                log("❌ All hierarchical signatures failed verification - critical error", "error");
            }
        }
        
        return {
            keygenResults: incompleteKeyShares,
            auxgenResults: auxGenResults,
            signingResults: signingResults
        };
        
    } catch (error) {
        log(`Hierarchical pipeline test failed: ${error.message}`, "error");
        log(`Error details: ${error.stack}`, "error");
        throw error;
    }
}

// Browser-specific functions
function setupBrowserEventListeners() {
    if (typeof document === 'undefined') return;

    // Full pipeline test button
    const fullPipelineBtn = document.getElementById('fullHierarchicalPipelineBtn');
    if (fullPipelineBtn) {
        fullPipelineBtn.addEventListener('click', async () => {
            fullPipelineBtn.disabled = true;
            fullPipelineBtn.textContent = '🔄 Running...';
            
            try {
                await runFullHierarchicalPipelineTest();
            } catch (error) {
               console.log(`Hierarchical pipeline test failed: ${JSON.stringify(error)}`);
            }
        });
    }

    // Keygen only button
    const keygenOnlyBtn = document.getElementById('hierarchicalKeygenOnlyBtn');
    if (keygenOnlyBtn) {
        keygenOnlyBtn.addEventListener('click', async () => {
            keygenOnlyBtn.disabled = true;
            keygenOnlyBtn.textContent = '🔄 Running...';
            
            try {
                await initializeWasm();
                await runHierarchicalKeyGeneration();
            } catch (error) {
                log(`Hierarchical Keygen test failed: ${error.message}`, "error");
            } finally {
                keygenOnlyBtn.disabled = false;
                keygenOnlyBtn.textContent = '🔑 Run Hierarchical Keygen Only';
            }
        });
    }

    // AuxGen only button
    const auxgenOnlyBtn = document.getElementById('hierarchicalAuxgenOnlyBtn');
    if (auxgenOnlyBtn) {
        auxgenOnlyBtn.addEventListener('click', async () => {
            auxgenOnlyBtn.disabled = true;
            auxgenOnlyBtn.textContent = '🔄 Running...';
            
            try {
                await initializeWasm();
                log("Note: Running with mock incomplete key shares", "round");
                const mockShares = Array(4).fill(null).map((_, i) => ({ mock: true, index: i }));
                await runHierarchicalAuxGeneration(mockShares);
            } catch (error) {
                log(`Hierarchical AuxGen test failed: ${error.message}`, "error");
            } finally {
                auxgenOnlyBtn.disabled = false;
                auxgenOnlyBtn.textContent = '⚙️ Run Hierarchical AuxGen Only';
            }
        });
    }

    // Hierarchical Signing only button
    const signingOnlyBtn = document.getElementById('hierarchicalSigningOnlyBtn');
    if (signingOnlyBtn) {
        signingOnlyBtn.addEventListener('click', async () => {
            signingOnlyBtn.disabled = true;
            signingOnlyBtn.textContent = '🔄 Running...';
            
            try {
                await initializeWasm();
                log("Note: Running with mock complete key shares", "round");
                const mockCompleteShares = Array(4).fill(null).map((_, i) => ({ 
                    mock: true, 
                    index: i,
                    core: { mock: true },
                    aux: { mock: true },
                    party_index: i,
                    rank: parties[i].ranks[i]
                }));
                await runHierarchicalSigning(mockCompleteShares);
            } catch (error) {
                log(`Hierarchical Signing test failed: ${error.message}`, "error");
            } finally {
                signingOnlyBtn.disabled = false;
                signingOnlyBtn.textContent = '✍️ Run Hierarchical Signing Only';
            }
        });
    }

    // Validate configuration button
    const validateBtn = document.getElementById('validateHierarchicalBtn');
    if (validateBtn) {
        validateBtn.addEventListener('click', async () => {
            try {
                const result = await validateHierarchicalConfiguration();
                log(`Configuration validation result:`, "success");
                log(`- Threshold: ${result.t}`, "success");
                log(`- Parties: ${result.n}`, "success");
                log(`- Ranks: [${result.ranks.join(',')}]`, "success");
                log(`- Valid authorized sets: ${result.validSets}`, "success");
            } catch (error) {
                log(`Configuration validation failed: ${error.message}`, "error");
            }
        });
    }

    // Clear button
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            const output = document.getElementById('output');
            if (output) {
                output.textContent = 'Output cleared. Ready for new hierarchical test...\n';
            }
            updateProgressBar('Ready', 0, 'Click a button to start');
        });
    }

    // Cache management buttons
    const clearCacheBtn = document.getElementById('clearCacheBtn');
    if (clearCacheBtn) {
        clearCacheBtn.addEventListener('click', () => {
            const cleared = CacheManager.clearAll();
            log(`🗑️ Cleared ${cleared} cache entries`, "success");
        });
    }

    const showCacheBtn = document.getElementById('showCacheBtn');
    if (showCacheBtn) {
        showCacheBtn.addEventListener('click', () => {
            const stats = CacheManager.getStats();
            const items = CacheManager.list();
            
            log(`📊 Cache Statistics:`, "success");
            log(`- Total entries: ${stats.count}`, "success");
            log(`- Total size: ${stats.totalSize}`, "success");
            log(`- Phases cached: ${stats.phases.join(', ')}`, "success");
            
            if (items.length > 0) {
                log(`📋 Cache Contents:`, "success");
                items.forEach(item => {
                    log(`- ${item.phase}:${item.round} - ${item.size} (${item.age} old)`, "success");
                });
            } else {
                log(`- No cache entries found`, "success");
            }
        });
    }
}

// Initialize browser environment
async function initializeBrowser() {
    if (typeof window !== 'undefined') {
        log("🔐 Hierarchical CGGMP21 Full Pipeline Test Ready");
        log("Initializing Hierarchical Web Worker for heavy computations...");
        
        // Initialize worker and set progress callback
        try {
            await hierarchicalWorkerManager.initialize();
            console.log('🔧 Setting hierarchical progress callback...');
            hierarchicalWorkerManager.setProgressCallback((progressData) => {
                console.log('🎯 Hierarchical Progress callback invoked with:', progressData);
                const { phase, round, message, progress } = progressData;
                log(`${phase} ${round}: ${message}`, round ? "round" : "phase");
                updateProgressBar(phase, progress, message);
            });
            console.log('✅ Hierarchical Progress callback set successfully');
            
            log("Hierarchical Worker and progress callback initialized successfully");
            log("Click 'Run Hierarchical Pipeline Test' to start the complete hierarchical protocol test");
            setupBrowserEventListeners();
        } catch (error) {
            log(`Failed to initialize hierarchical worker: ${error.message}`, "error");
            log("Setting up event listeners without hierarchical worker support");
            setupBrowserEventListeners();
        }
    }
}

// Auto-initialize if in browser environment
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', async () => {
            await initializeBrowser();
        });
    } else {
        initializeBrowser();
    }
}

// For Node.js or direct script execution
if (typeof module !== 'undefined') {
    module.exports = { 
        runFullHierarchicalPipelineTest,
        runHierarchicalKeyGeneration,
        runHierarchicalAuxGeneration,
        validateHierarchicalConfiguration,
        initializeWasm,
        log,
        CacheManager
    };
}

// Export individual test functions for debugging
export { 
    runHierarchicalKeyGeneration, 
    runHierarchicalAuxGeneration, 
    runHierarchicalSigning,
    runFullHierarchicalPipelineTest,
    validateHierarchicalConfiguration,
    initializeWasm,
    log,
    setupBrowserEventListeners,
    hierarchicalWorkerManager,
    CacheManager
};