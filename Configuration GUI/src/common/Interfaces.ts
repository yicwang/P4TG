/* Copyright 2022-present University of Tuebingen, Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Steffen Lindner (steffen.lindner@uni-tuebingen.de)
 */


export interface MPLSHeader {
    label: number,
    tc: number,
    ttl: number
}

export interface Statistics {
    sample_mode: boolean,
    tx_rate_l1: { [name: string]: number },
    tx_rate_l2: { [name: string]: number },
    rx_rate_l1: { [name: string]: number },
    rx_rate_l2: { [name: string]: number },
    frame_size: { [name: string]: { tx: { low: number, high: number, packets: number }[], rx: { low: number, high: number, packets: number }[] } },
    iats: {
        [name: string]: { tx: { mean: number, std: number, n: number, mae: number }, rx: { mean: number, std: number, n: number, mae: number } }
    }
    frame_type_data: { [name: string]: { tx: { multicast: number, broadcast: number, unicast: number, total: number, "non-unicast": number }, rx: { multicast: number, broadcast: number, unicast: number, total: number, "non-unicast": number } } },
    rtts: { [name: string]: { mean: number, current: number, min: number, max: number, jitter: number, n: number } },
    packet_loss: { [name: string]: number },
    app_tx_l2: {
        [name: string]: {
            [name: string]: number
        }
    },
    app_rx_l2: {
        [name: string]: {
            [name: string]: number
        }
    },
    out_of_order: { [name: string]: number },
    elapsed_time: number
}

export const StatisticsObject: Statistics = {
    sample_mode: false,
    frame_size: {},
    frame_type_data: {},
    rx_rate_l1: {},
    rx_rate_l2: {},
    tx_rate_l1: {},
    tx_rate_l2: {},
    iats: {},
    rtts: {},
    packet_loss: {},
    app_tx_l2: {},
    app_rx_l2: {},
    out_of_order: {},
    elapsed_time: 0
}

export interface TimeStatistics {
    tx_rate_l1: { [name: number]: {
        [name: number]: number
        } },
    rx_rate_l1: { [name: number]: {
            [name: number]: number
        } },
}

export const TimeStatisticsObject: TimeStatistics = {
    tx_rate_l1: {},
    rx_rate_l1: {}
}

export interface StreamSettings {
    mpls_stack: MPLSHeader[],
    port: number,
    stream_id: number,
    vlan_id: number,
    pcp: number,
    dei: number,
    inner_vlan_id: number,
    inner_pcp: number,
    inner_dei: number,
    eth_src: string,
    eth_dst: string,
    ip_src: string,
    ip_dst: string,
    ip_tos: number,
    ip_src_mask: string,
    ip_dst_mask: string,
    active: boolean
}

export enum Encapsulation {
    None,
    Q,
    QinQ,
    MPLS
}

export enum GenerationMode {
    NONE = 0,
    CBR = 1,
    MPPS = 2,
    POISSON = 3,
    ANALYZE = 4,
}
export interface Stream {
    stream_id: number,
    frame_size: number,
    encapsulation: Encapsulation,
    number_of_lse: number,
    traffic_rate: number,
    app_id: number
    burst: number
}

export const DefaultMPLSHeader = () => {
    let lse: MPLSHeader = {
        label: 20,
        tc: 0,
        ttl: 64
    }
    return lse
}

export const DefaultStream = (id: number) => {
    let stream: Stream = {
        stream_id: id,
        app_id: id,
        frame_size: 1024,
        encapsulation: Encapsulation.None,
        number_of_lse: 0,
        traffic_rate: 1,
        burst: 1
    }

    return stream
}

export const DefaultStreamSettings = (id: number, port: number) => {
    let stream: StreamSettings = {
        port: port,
        stream_id: id,
        vlan_id: 1,
        pcp: 0,
        dei: 0,
        inner_vlan_id: 1,
        inner_pcp: 0,
        inner_dei: 0,
        mpls_stack: [],
        eth_src: "3B:D5:42:2A:F6:92",
        eth_dst: "81:E7:9D:E3:AD:47",
        ip_src: "192.168.178.10",
        ip_dst: "192.168.178.11",
        ip_tos: 0,
        ip_src_mask: "0.0.0.0",
        ip_dst_mask: "0.0.0.0",
        active: false
    }

    return stream
}