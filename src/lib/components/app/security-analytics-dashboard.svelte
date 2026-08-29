<script lang="ts">
	import { onMount } from 'svelte';
	import ShieldIcon from '@lucide/svelte/icons/shield';
	import ShieldAlertIcon from '@lucide/svelte/icons/shield-alert';
	import ShieldCheckIcon from '@lucide/svelte/icons/shield-check';
	import LockIcon from '@lucide/svelte/icons/lock';
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import CpuIcon from '@lucide/svelte/icons/cpu';
	import DatabaseIcon from '@lucide/svelte/icons/database';

	interface TelemetryData {
		avgRiskScore: number;
		threatVectors: Record<string, number>;
		riskHistogram: number[];
		mfaStats: {
			totalUsers: number;
			mfaEnrolledUsers: number;
			adoptionRate: number;
		};
		merkleAudit: {
			isValid: boolean;
			totalRecords: number;
			merkleRoot: string;
			tamperedCount: number;
			message: string;
		};
		recentThreatCount: number;
	}

	let loading = $state(true);
	let verifyingMerkle = $state(false);
	let error = $state<string | null>(null);
	let telemetry = $state<TelemetryData | null>(null);

	async function loadTelemetry() {
		loading = true;
		error = null;
		try {
			const res = await fetch('/api/security/telemetry', { credentials: 'include' });
			if (!res.ok) throw new Error(`HTTP error ${res.status}`);
			telemetry = await res.json();
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}

	async function runMerkleVerify() {
		verifyingMerkle = true;
		try {
			const res = await fetch('/api/security/merkle-verify', { credentials: 'include' });
			const result = await res.json();
			if (telemetry) {
				telemetry.merkleAudit = {
					isValid: result.isValid,
					totalRecords: result.totalRecords,
					merkleRoot: result.merkleRoot,
					tamperedCount: result.tamperedRecords?.length || 0,
					message: result.verificationMessage
				};
			}
		} catch (e) {
			alert('Verification failed: ' + String(e));
		} finally {
			verifyingMerkle = false;
		}
	}

	onMount(() => {
		loadTelemetry();
	});
</script>

<div class="space-y-6 rounded-xl border border-slate-800 bg-slate-950 p-6 text-slate-100 shadow-2xl">
	<!-- Top Bar -->
	<div class="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
		<div class="flex items-center gap-3">
			<div class="rounded-lg bg-emerald-500/10 p-2.5 text-emerald-400 border border-emerald-500/20">
				<ShieldIcon class="h-6 w-6" />
			</div>
			<div>
				<h2 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
					Cybersecurity Intelligence & ML Threat Command Center
					<span class="inline-flex items-center rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-500/30">
						LIVE ACTIVE DEFENSE
					</span>
				</h2>
				<p class="text-xs text-slate-400">Zero-Trust ABAC, 4FA Adaptive Auth, Merkle Tree Auditing & ML Anomaly Detection</p>
			</div>
		</div>

		<button
			onclick={loadTelemetry}
			disabled={loading}
			class="flex items-center gap-2 rounded-lg bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-xs font-medium transition cursor-pointer text-slate-200"
		>
			<RefreshCwIcon class="h-3.5 w-3.5 {loading ? 'animate-spin' : ''}" />
			Refresh Telemetry
		</button>
	</div>

	{#if loading && !telemetry}
		<div class="flex h-48 items-center justify-center text-slate-400">
			<RefreshCwIcon class="h-6 w-6 animate-spin text-emerald-400" />
			<span class="ml-2 text-sm">Analyzing security metrics & computing Merkle tree hashes...</span>
		</div>
	{:else if error}
		<div class="rounded-lg bg-red-950/50 p-4 border border-red-800 text-red-300 text-sm">
			Failed to load security telemetry: {error}
		</div>
	{:else if telemetry}
		<!-- KPI Summary Cards -->
		<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
			<!-- ML Risk Score Card -->
			<div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
				<div class="flex items-center justify-between text-slate-400 text-xs font-medium">
					<span>ML Threat Risk Index</span>
					<CpuIcon class="h-4 w-4 text-cyan-400" />
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-2xl font-bold text-white">{telemetry.avgRiskScore}</span>
					<span class="text-xs text-slate-400">/ 100</span>
					<span class="ml-auto rounded px-2 py-0.5 text-[10px] font-bold {telemetry.avgRiskScore < 30 ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'}">
						{telemetry.avgRiskScore < 30 ? 'LOW RISK' : 'ELEVATED'}
					</span>
				</div>
				<p class="mt-1 text-[11px] text-slate-400">Multivariate Anomaly Engine Active</p>
			</div>

			<!-- Merkle Audit Chain -->
			<div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
				<div class="flex items-center justify-between text-slate-400 text-xs font-medium">
					<span>Merkle Tree Audit Chain</span>
					<DatabaseIcon class="h-4 w-4 text-emerald-400" />
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-2xl font-bold text-emerald-400">{telemetry.merkleAudit.isValid ? 'VERIFIED' : 'TAMPERED'}</span>
				</div>
				<p class="mt-1 text-[11px] text-slate-400 font-mono text-ellipsis overflow-hidden whitespace-nowrap">
					Root: {telemetry.merkleAudit.merkleRoot.slice(0, 14)}...
				</p>
			</div>

			<!-- 2FA/3FA/4FA Auth Rate -->
			<div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
				<div class="flex items-center justify-between text-slate-400 text-xs font-medium">
					<span>Multi-Factor (2FA/3FA/4FA)</span>
					<LockIcon class="h-4 w-4 text-purple-400" />
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-2xl font-bold text-white">{telemetry.mfaStats.adoptionRate}%</span>
					<span class="text-xs text-slate-400">Enrolled</span>
				</div>
				<p class="mt-1 text-[11px] text-slate-400">Risk-Adaptive Step-up Policy Active</p>
			</div>

			<!-- Honeypot & Threat Traps -->
			<div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
				<div class="flex items-center justify-between text-slate-400 text-xs font-medium">
					<span>Active Honeypot Traps</span>
					<ShieldAlertIcon class="h-4 w-4 text-amber-400" />
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-2xl font-bold text-amber-300">{telemetry.recentThreatCount}</span>
					<span class="text-xs text-slate-400">Events Logged</span>
				</div>
				<p class="mt-1 text-[11px] text-slate-400">Deception Technology Operational</p>
			</div>
		</div>

		<!-- Interactive Visual Graphs Grid -->
		<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">

			<!-- Graph 1: Threat Vector Radar / Distribution Chart -->
			<div class="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
				<h3 class="text-sm font-semibold text-slate-200 flex items-center justify-between">
					<span>Graph 1: Threat Vector Distribution Radar</span>
					<span class="text-xs text-slate-400 font-normal">Real-Time Threat Classifier</span>
				</h3>
				<div class="mt-4 space-y-3">
					{#each Object.entries(telemetry.threatVectors) as [vector, count]}
						<div>
							<div class="flex justify-between text-xs text-slate-300 mb-1">
								<span>{vector}</span>
								<span class="font-bold text-cyan-400">{count} events</span>
							</div>
							<div class="h-2.5 w-full rounded-full bg-slate-800 overflow-hidden">
								<div
									class="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500"
									style="width: {Math.min(100, Math.max(8, (count + 1) * 20))}%"
								></div>
							</div>
						</div>
					{/each}
				</div>
			</div>

			<!-- Graph 2: ML Risk Score Distribution Histogram -->
			<div class="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
				<h3 class="text-sm font-semibold text-slate-200 flex items-center justify-between">
					<span>Graph 2: ML Anomaly Threat Score Histogram</span>
					<span class="text-xs text-slate-400 font-normal">0 - 100 Risk Bins</span>
				</h3>
				<div class="mt-6 flex h-40 items-end justify-between gap-3 px-2">
					{#each telemetry.riskHistogram as val, idx}
						<div class="flex flex-1 flex-col items-center gap-2">
							<span class="text-[10px] font-bold text-slate-300">{val}</span>
							<div
								class="w-full rounded-t-md bg-gradient-to-t from-purple-600 to-indigo-400 transition-all duration-500"
								style="height: {Math.max(12, val * 25)}px"
							></div>
							<span class="text-[10px] text-slate-400">{idx * 20}-{(idx + 1) * 20}</span>
						</div>
					{/each}
				</div>
			</div>

			<!-- Graph 3: Cryptographic Merkle Audit Verification Gauge -->
			<div class="rounded-xl border border-slate-800 bg-slate-900/70 p-5 lg:col-span-2">
				<div class="flex flex-wrap items-center justify-between gap-3">
					<div>
						<h3 class="text-sm font-semibold text-slate-200 flex items-center gap-2">
							<DatabaseIcon class="h-4 w-4 text-emerald-400" />
							Graph 3: Cryptographic Merkle Tree Hash-Chain Tamper Detection
						</h3>
						<p class="text-xs text-slate-400 mt-0.5">SHA-256 Sequential Hash Chaining of {telemetry.merkleAudit.totalRecords} Audit Log Records</p>
					</div>

					<button
						onclick={runMerkleVerify}
						disabled={verifyingMerkle}
						class="flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-xs font-semibold text-white transition cursor-pointer"
					>
						<ShieldCheckIcon class="h-4 w-4" />
						{verifyingMerkle ? 'Verifying Merkle Tree...' : 'Run Cryptographic Audit Check'}
					</button>
				</div>

				<div class="mt-4 rounded-lg bg-slate-950 p-4 border border-slate-800">
					<div class="flex items-center justify-between">
						<span class="text-xs font-mono text-slate-400">Merkle Root Hash:</span>
						<span class="text-xs font-mono text-emerald-400 font-bold">{telemetry.merkleAudit.merkleRoot}</span>
					</div>
					<div class="mt-2 flex items-center gap-2 text-xs text-slate-300">
						<span class="h-2.5 w-2.5 rounded-full {telemetry.merkleAudit.isValid ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}"></span>
						{telemetry.merkleAudit.message}
					</div>
				</div>
			</div>

		</div>
	{/if}
</div>
