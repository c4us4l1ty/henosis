//! Compressed Sparse Row (CSR) directed capability hypergraph.
//!
//! Stores node-to-hyperedge and hyperedge-to-prerequisite incidences in flat,
//! cache-contiguous index arrays so forward feasibility closure `F(H)`,
//! expansion deltas `Delta F`, backward light-cones, ancestor depth propagation,
//! and multi-peer compositional synergy `Delta F_syn(H_A, H_B)` execute in
//! linear time `O(|V| + sum |P_e|)` without pointer-heavy graph allocations.
//!
//! Refuted contracts are excluded from feasibility propagation. Reachability in
//! the hypergraph represents a *candidate feasible route* given recorded contracts,
//! not proof that an untested contract will succeed in reality.

use crate::model::{EpistemicStatus, RealizationContract};
use crate::WorldState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone)]
struct IndexedContract {
    id: String,
    output: u32,
    cost_units: u32,
    status: EpistemicStatus,
}

/// Immutable CSR topological index compiled from active contracts and nodes.
#[derive(Debug, Clone)]
pub struct CsrHypergraph {
    idx_to_node: Vec<String>,
    node_to_idx: BTreeMap<String, u32>,
    contracts: Vec<IndexedContract>,
    contract_to_idx: BTreeMap<String, u32>,
    // Forward hyperedge prerequisites: prereqs(e) = edge_prereqs[edge_offsets[e]..edge_offsets[e+1]]
    edge_offsets: Vec<usize>,
    edge_prereqs: Vec<u32>,
    // Node -> dependent hyperedges: uses(v) = node_use_edges[node_use_offsets[v]..node_use_offsets[v+1]]
    node_use_offsets: Vec<usize>,
    node_use_edges: Vec<u32>,
    // Output node -> producing hyperedges: prods(v) = node_prod_edges[node_prod_offsets[v]..node_prod_offsets[v+1]]
    node_prod_offsets: Vec<usize>,
    node_prod_edges: Vec<u32>,
}

/// Forward feasibility closure `F(H)` starting from a base set `H`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeasibleClosure {
    pub reachable_nodes: BTreeSet<String>,
    pub newly_unlocked_nodes: BTreeSet<String>,
    pub executable_contracts: Vec<String>,
}

/// Expansion delta `Delta F = F(H') \ F(H)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpansionDelta {
    pub unlocked_nodes: BTreeSet<String>,
    pub unlocked_contracts: Vec<String>,
}

/// Goal-conditioned backward light-cone isolating load-bearing dependencies of
/// `target` while discarding unrelated nodes as zero-leverage dust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackwardLightCone {
    pub target: String,
    pub already_feasible: bool,
    pub spine_contracts: Vec<String>,
    pub verified_foundations: Vec<String>,
    pub missing_capabilities: Vec<String>,
    /// Contracts in the light-cone whose prerequisites are all already in `H`.
    pub immediately_executable: Vec<String>,
    pub total_missing_cost_units: u64,
    pub ignored_dust_nodes: usize,
}

/// Compositional leverage report between two peers' verified capability sets:
/// `Delta F_syn(H_A, H_B) = F(H_A U H_B) \ (F(H_A) U F(H_B))`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynergyReport {
    pub solo_a_reachable: BTreeSet<String>,
    pub solo_b_reachable: BTreeSet<String>,
    pub combined_reachable: BTreeSet<String>,
    pub emergent_nodes: BTreeSet<String>,
    pub emergent_contracts: Vec<String>,
    pub shared_base: BTreeSet<String>,
    pub unique_to_a: BTreeSet<String>,
    pub unique_to_b: BTreeSet<String>,
}

impl CsrHypergraph {
    pub fn from_state(state: &WorldState) -> Self {
        let active: Vec<&RealizationContract> = state
            .contracts
            .values()
            .filter(|c| c.status != EpistemicStatus::Refuted)
            .collect();
        let node_ids: BTreeSet<&str> = state
            .nodes
            .keys()
            .map(String::as_str)
            .chain(active.iter().flat_map(|c| {
                c.prerequisites
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(c.output.as_str()))
            }))
            .collect();
        Self::build(node_ids, &active)
    }

    pub fn from_contracts(contracts: &[RealizationContract]) -> Self {
        let active: Vec<&RealizationContract> = contracts
            .iter()
            .filter(|c| c.status != EpistemicStatus::Refuted)
            .collect();
        let node_ids: BTreeSet<&str> = active
            .iter()
            .flat_map(|c| {
                c.prerequisites
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(c.output.as_str()))
            })
            .collect();
        Self::build(node_ids, &active)
    }

    fn build(node_ids: BTreeSet<&str>, active: &[&RealizationContract]) -> Self {
        let mut idx_to_node = Vec::with_capacity(node_ids.len());
        let mut node_to_idx = BTreeMap::new();
        for (idx, id) in node_ids.into_iter().enumerate() {
            let idx_u32 = idx as u32;
            idx_to_node.push(id.to_owned());
            node_to_idx.insert(id.to_owned(), idx_u32);
        }

        let n_nodes = idx_to_node.len();
        let n_edges = active.len();

        let mut contracts = Vec::with_capacity(n_edges);
        let mut contract_to_idx = BTreeMap::new();
        let mut edge_offsets = Vec::with_capacity(n_edges + 1);
        let mut edge_prereqs = Vec::new();
        let mut use_counts = vec![0usize; n_nodes];
        let mut prod_counts = vec![0usize; n_nodes];

        edge_offsets.push(0);
        for (e_idx, contract) in active.iter().enumerate() {
            let e_u32 = e_idx as u32;
            let out_u32 = node_to_idx[contract.output.as_str()];
            contract_to_idx.insert(contract.id.clone(), e_u32);
            contracts.push(IndexedContract {
                id: contract.id.clone(),
                output: out_u32,
                cost_units: contract.cost_units,
                status: contract.status,
            });
            prod_counts[out_u32 as usize] += 1;

            let mut prereq_indices: Vec<u32> = contract
                .prerequisites
                .iter()
                .map(|p| node_to_idx[p.as_str()])
                .collect();
            prereq_indices.sort_unstable();
            prereq_indices.dedup();
            for &p in &prereq_indices {
                use_counts[p as usize] += 1;
                edge_prereqs.push(p);
            }
            edge_offsets.push(edge_prereqs.len());
        }

        // Prefix sums for node_use and node_prod CSR arrays.
        let mut node_use_offsets = Vec::with_capacity(n_nodes + 1);
        node_use_offsets.push(0);
        for &c in &use_counts {
            node_use_offsets.push(node_use_offsets.last().copied().unwrap_or(0) + c);
        }
        let mut node_use_edges = vec![0u32; *node_use_offsets.last().unwrap_or(&0)];
        let mut use_cursor = node_use_offsets[..n_nodes].to_vec();

        let mut node_prod_offsets = Vec::with_capacity(n_nodes + 1);
        node_prod_offsets.push(0);
        for &c in &prod_counts {
            node_prod_offsets.push(node_prod_offsets.last().copied().unwrap_or(0) + c);
        }
        let mut node_prod_edges = vec![0u32; *node_prod_offsets.last().unwrap_or(&0)];
        let mut prod_cursor = node_prod_offsets[..n_nodes].to_vec();

        for (e_idx, contract) in contracts.iter().enumerate() {
            let e_u32 = e_idx as u32;
            for &p in &edge_prereqs[edge_offsets[e_idx]..edge_offsets[e_idx + 1]] {
                let slot = &mut use_cursor[p as usize];
                node_use_edges[*slot] = e_u32;
                *slot += 1;
            }
            let out_slot = &mut prod_cursor[contract.output as usize];
            node_prod_edges[*out_slot] = e_u32;
            *out_slot += 1;
        }

        Self {
            idx_to_node,
            node_to_idx,
            contracts,
            contract_to_idx,
            edge_offsets,
            edge_prereqs,
            node_use_offsets,
            node_use_edges,
            node_prod_offsets,
            node_prod_edges,
        }
    }

    pub fn node_count(&self) -> usize {
        self.idx_to_node.len()
    }

    pub fn contract_count(&self) -> usize {
        self.contracts.len()
    }

    pub fn node_ids(&self) -> &[String] {
        &self.idx_to_node
    }

    /// Number of active hyperedges that directly list `node_id` as a prerequisite.
    pub fn direct_out_degree(&self, node_id: &str) -> usize {
        let Some(&v) = self.node_to_idx.get(node_id) else {
            return 0;
        };
        let i = v as usize;
        self.node_use_offsets[i + 1] - self.node_use_offsets[i]
    }

    /// Contract status lookup for callers weighting confidence.
    pub fn contract_status(&self, contract_id: &str) -> Option<EpistemicStatus> {
        let &idx = self.contract_to_idx.get(contract_id)?;
        Some(self.contracts[idx as usize].status)
    }

    fn prereqs(&self, e: usize) -> &[u32] {
        &self.edge_prereqs[self.edge_offsets[e]..self.edge_offsets[e + 1]]
    }

    fn uses(&self, v: usize) -> &[u32] {
        &self.node_use_edges[self.node_use_offsets[v]..self.node_use_offsets[v + 1]]
    }

    fn prods(&self, v: usize) -> &[u32] {
        &self.node_prod_edges[self.node_prod_offsets[v]..self.node_prod_offsets[v + 1]]
    }

    /// Linear-time Horn-hypergraph forward closure `F(H)`: an operation `e`
    /// fires iff *every* prerequisite in `P_e` is simultaneously reachable.
    pub fn feasible_closure(&self, base: &BTreeSet<String>) -> FeasibleClosure {
        let n_nodes = self.idx_to_node.len();
        let n_edges = self.contracts.len();
        let mut reachable = vec![false; n_nodes];
        let mut fired = vec![false; n_edges];
        let mut remaining: Vec<usize> = (0..n_edges).map(|e| self.prereqs(e).len()).collect();
        let mut queue = VecDeque::new();

        for name in base {
            if let Some(&v) = self.node_to_idx.get(name) {
                let vi = v as usize;
                if !reachable[vi] {
                    reachable[vi] = true;
                    queue.push_back(vi);
                }
            }
        }

        // Contracts with zero prerequisites are immediately executable.
        for (e, &rem) in remaining.iter().enumerate() {
            if rem == 0 && !fired[e] {
                fired[e] = true;
                let out = self.contracts[e].output as usize;
                if !reachable[out] {
                    reachable[out] = true;
                    queue.push_back(out);
                }
            }
        }

        while let Some(v) = queue.pop_front() {
            for &e_u32 in self.uses(v) {
                let e = e_u32 as usize;
                if fired[e] {
                    continue;
                }
                remaining[e] = remaining[e].saturating_sub(1);
                if remaining[e] == 0 {
                    fired[e] = true;
                    let out = self.contracts[e].output as usize;
                    if !reachable[out] {
                        reachable[out] = true;
                        queue.push_back(out);
                    }
                }
            }
        }

        let mut reachable_nodes: BTreeSet<String> = base.clone();
        let mut newly_unlocked_nodes = BTreeSet::new();
        for (idx, &is_reach) in reachable.iter().enumerate() {
            if is_reach {
                let name = &self.idx_to_node[idx];
                reachable_nodes.insert(name.clone());
                if !base.contains(name) {
                    newly_unlocked_nodes.insert(name.clone());
                }
            }
        }

        let mut executable_contracts: Vec<String> = fired
            .iter()
            .enumerate()
            .filter_map(|(e, &ok)| ok.then(|| self.contracts[e].id.clone()))
            .collect();
        executable_contracts.sort();

        FeasibleClosure {
            reachable_nodes,
            newly_unlocked_nodes,
            executable_contracts,
        }
    }

    /// Compute exact expansion `Delta F = F(after) \ F(before)`.
    pub fn expansion_delta(
        &self,
        before: &BTreeSet<String>,
        after: &BTreeSet<String>,
    ) -> ExpansionDelta {
        let f_before = self.feasible_closure(before);
        let f_after = self.feasible_closure(after);
        let before_contracts: BTreeSet<&str> = f_before
            .executable_contracts
            .iter()
            .map(String::as_str)
            .collect();
        let unlocked_nodes = f_after
            .reachable_nodes
            .difference(&f_before.reachable_nodes)
            .cloned()
            .collect();
        let unlocked_contracts = f_after
            .executable_contracts
            .into_iter()
            .filter(|id| !before_contracts.contains(id.as_str()))
            .collect();
        ExpansionDelta {
            unlocked_nodes,
            unlocked_contracts,
        }
    }

    /// Trace the backward light-cone of `target` against verified set `verified`,
    /// pruning recursion at verified foundations and ignoring unrelated graph dust.
    pub fn backward_light_cone(
        &self,
        target: &str,
        verified: &BTreeSet<String>,
    ) -> Result<BackwardLightCone, String> {
        let Some(&target_idx) = self.node_to_idx.get(target) else {
            return Err(format!("unknown target node '{target}'"));
        };
        let closure = self.feasible_closure(verified);
        let already_feasible = closure.reachable_nodes.contains(target);

        let n_nodes = self.idx_to_node.len();
        let n_edges = self.contracts.len();
        let mut visited_nodes = vec![false; n_nodes];
        let mut spine_edge_flags = vec![false; n_edges];
        let mut verified_foundations = BTreeSet::new();
        let mut missing_capabilities = BTreeSet::new();
        let mut queue = VecDeque::new();

        visited_nodes[target_idx as usize] = true;
        if verified.contains(target) {
            verified_foundations.insert(target.to_owned());
        } else {
            missing_capabilities.insert(target.to_owned());
            queue.push_back(target_idx as usize);
        }

        while let Some(v) = queue.pop_front() {
            for &e_u32 in self.prods(v) {
                let e = e_u32 as usize;
                if spine_edge_flags[e] {
                    continue;
                }
                spine_edge_flags[e] = true;
                for &p_u32 in self.prereqs(e) {
                    let p = p_u32 as usize;
                    let name = &self.idx_to_node[p];
                    if verified.contains(name) {
                        visited_nodes[p] = true;
                        verified_foundations.insert(name.clone());
                    } else {
                        missing_capabilities.insert(name.clone());
                        if !visited_nodes[p] {
                            visited_nodes[p] = true;
                            queue.push_back(p);
                        }
                    }
                }
            }
        }

        let mut spine_contracts = Vec::new();
        let mut immediately_executable = Vec::new();
        let mut total_missing_cost_units = 0u64;
        for (e, &in_spine) in spine_edge_flags.iter().enumerate() {
            if !in_spine {
                continue;
            }
            let c = &self.contracts[e];
            spine_contracts.push(c.id.clone());
            let out_name = &self.idx_to_node[c.output as usize];
            if !verified.contains(out_name) {
                total_missing_cost_units =
                    total_missing_cost_units.saturating_add(u64::from(c.cost_units));
            }
            let all_prereqs_verified = self
                .prereqs(e)
                .iter()
                .all(|&p| verified.contains(&self.idx_to_node[p as usize]));
            if all_prereqs_verified && !verified.contains(out_name) {
                immediately_executable.push(c.id.clone());
            }
        }
        spine_contracts.sort();
        immediately_executable.sort();

        let touched = visited_nodes.iter().filter(|&&b| b).count();
        let ignored_dust_nodes = n_nodes.saturating_sub(touched);

        Ok(BackwardLightCone {
            target: target.to_owned(),
            already_feasible,
            spine_contracts,
            verified_foundations: verified_foundations.into_iter().collect(),
            missing_capabilities: missing_capabilities.into_iter().collect(),
            immediately_executable,
            total_missing_cost_units,
            ignored_dust_nodes,
        })
    }

    /// Return all prerequisite ancestor nodes of `contract_id` along with their
    /// minimum topological depth (`1` = direct prerequisite, `2` = prerequisite
    /// of a prerequisite, etc.) for backward skill-retention replenishment.
    pub fn prerequisite_ancestors(&self, contract_id: &str) -> Result<Vec<(String, usize)>, String> {
        let Some(&e_idx) = self.contract_to_idx.get(contract_id) else {
            return Err(format!("unknown or refuted contract '{contract_id}'"));
        };
        let mut depth_by_node: BTreeMap<u32, usize> = BTreeMap::new();
        let mut queue = VecDeque::new();
        for &p in self.prereqs(e_idx as usize) {
            if depth_by_node.insert(p, 1).is_none() {
                queue.push_back((p, 1usize));
            }
        }
        while let Some((node, depth)) = queue.pop_front() {
            for &prod_e in self.prods(node as usize) {
                for &anc in self.prereqs(prod_e as usize) {
                    if let std::collections::btree_map::Entry::Vacant(slot) =
                        depth_by_node.entry(anc)
                    {
                        slot.insert(depth + 1);
                        queue.push_back((anc, depth + 1));
                    }
                }
            }
        }
        Ok(depth_by_node
            .into_iter()
            .map(|(idx, d)| (self.idx_to_node[idx as usize].clone(), d))
            .collect())
    }

    /// Compute compositional leverage between two sovereign peers:
    /// `Delta F_syn(H_A, H_B) = F(H_A U H_B) \ (F(H_A) U F(H_B))`.
    pub fn compositional_synergy(
        &self,
        peer_a: &BTreeSet<String>,
        peer_b: &BTreeSet<String>,
    ) -> SynergyReport {
        let f_a = self.feasible_closure(peer_a);
        let f_b = self.feasible_closure(peer_b);
        let union_base: BTreeSet<String> = peer_a.union(peer_b).cloned().collect();
        let f_ab = self.feasible_closure(&union_base);

        let solo_union: BTreeSet<String> = f_a
            .reachable_nodes
            .union(&f_b.reachable_nodes)
            .cloned()
            .collect();
        let emergent_nodes: BTreeSet<String> = f_ab
            .reachable_nodes
            .difference(&solo_union)
            .cloned()
            .collect();

        let solo_contracts: BTreeSet<&str> = f_a
            .executable_contracts
            .iter()
            .chain(f_b.executable_contracts.iter())
            .map(String::as_str)
            .collect();
        let emergent_contracts: Vec<String> = f_ab
            .executable_contracts
            .into_iter()
            .filter(|id| !solo_contracts.contains(id.as_str()))
            .collect();

        SynergyReport {
            solo_a_reachable: f_a.reachable_nodes,
            solo_b_reachable: f_b.reachable_nodes,
            combined_reachable: f_ab.reachable_nodes,
            emergent_nodes,
            emergent_contracts,
            shared_base: peer_a.intersection(peer_b).cloned().collect(),
            unique_to_a: peer_a.difference(peer_b).cloned().collect(),
            unique_to_b: peer_b.difference(peer_a).cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(id: &str, prereqs: &[&str], output: &str, cost: u32) -> RealizationContract {
        RealizationContract {
            id: id.into(),
            title: id.into(),
            prerequisites: prereqs.iter().map(|s| (*s).to_owned()).collect(),
            assumptions: vec!["smooth field".into()],
            resources: vec!["workstation".into()],
            output: output.into(),
            verification: "reproduce benchmark within 1e-4".into(),
            failure_boundary: vec!["CFL > 1".into()],
            status: EpistemicStatus::Observed,
            cost_units: cost,
        }
        .normalized()
        .unwrap()
    }

    #[test]
    fn hypergraph_requires_joint_prerequisites_traces_lightcone_and_computes_synergy() {
        let contracts = vec![
            contract("c-ode", &["linear-algebra", "calculus"], "ode-solver", 3),
            contract(
                "c-pic",
                &["ode-solver", "electromagnetism", "parallel-simd"],
                "pic-plasma-sim",
                8,
            ),
            contract("c-unrelated-dust", &["trivia-a"], "trivia-b", 5),
        ];
        let hg = CsrHypergraph::from_contracts(&contracts);

        // Having linear-algebra alone unlocks nothing because c-ode needs BOTH prerequisites.
        let h_partial: BTreeSet<String> = ["linear-algebra".to_owned()].into_iter().collect();
        assert!(hg.feasible_closure(&h_partial).newly_unlocked_nodes.is_empty());

        // Peer A has math foundations; Peer B has physics + systems.
        let peer_a: BTreeSet<String> = ["linear-algebra", "calculus"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let peer_b: BTreeSet<String> = ["electromagnetism", "parallel-simd"]
            .into_iter()
            .map(str::to_owned)
            .collect();

        // Peer A alone reaches ode-solver, NOT pic-plasma-sim.
        let fa = hg.feasible_closure(&peer_a);
        assert!(fa.reachable_nodes.contains("ode-solver"));
        assert!(!fa.reachable_nodes.contains("pic-plasma-sim"));

        // Together, A U B discontinuously unlocks pic-plasma-sim via multi-step composition!
        let syn = hg.compositional_synergy(&peer_a, &peer_b);
        assert_eq!(
            syn.emergent_nodes,
            ["pic-plasma-sim".to_owned()].into_iter().collect()
        );
        assert_eq!(syn.emergent_contracts, vec!["c-pic".to_owned()]);

        // Backward light-cone from pic-plasma-sim ignores trivia-a and trivia-b as dust.
        let cone = hg.backward_light_cone("pic-plasma-sim", &peer_a).unwrap();
        assert!(!cone.already_feasible);
        assert_eq!(cone.spine_contracts, vec!["c-ode", "c-pic"]);
        assert_eq!(cone.immediately_executable, vec!["c-ode"]);
        assert_eq!(cone.ignored_dust_nodes, 2);
        assert!(cone.missing_capabilities.contains(&"electromagnetism".to_owned()));

        // Ancestor depths propagate from c-pic -> depth 1 (ode-solver, em, simd) -> depth 2 (la, calc).
        let ancestors = hg.prerequisite_ancestors("c-pic").unwrap();
        assert!(ancestors.contains(&("ode-solver".into(), 1)));
        assert!(ancestors.contains(&("linear-algebra".into(), 2)));
        assert!(!ancestors.iter().any(|(id, _)| id == "trivia-a"));
    }
}
