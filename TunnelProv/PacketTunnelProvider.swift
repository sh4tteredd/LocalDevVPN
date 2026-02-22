//
//  PacketTunnelProvider.swift
//  TunnelProv
//
//  Created by Stossy11 on 28/03/2025.
//

import NetworkExtension
import Darwin

class PacketTunnelProvider: NEPacketTunnelProvider {
    var tunnelDeviceIp: String = "10.7.0.0"
    var tunnelFakeIp: String = "10.7.0.1"
    var tunnelSubnetMask: String = "255.255.255.0"
    
    private var deviceIpValue: UInt32 = 0
    private var fakeIpValue: UInt32 = 0
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let useWifiSubnet = options?["UseWiFiSubnet"] as? Bool ?? false
        
        if useWifiSubnet {
            if let wifiInfo = getWiFiNetworkInfo() {
                tunnelDeviceIp = wifiInfo.ipAddress
                tunnelSubnetMask = wifiInfo.subnetMask
                let fakeIpParts = wifiInfo.ipAddress.split(separator: ".")
                if fakeIpParts.count == 4 {
                    tunnelFakeIp = "\(fakeIpParts[0]).\(fakeIpParts[1]).\(fakeIpParts[2]).\(Int(fakeIpParts[3])! + 1)"
                }
            }
        } else {
            if let deviceIp = options?["TunnelDeviceIP"] as? String {
                tunnelDeviceIp = deviceIp
            }
            if let fakeIp = options?["TunnelFakeIP"] as? String {
                tunnelFakeIp = fakeIp
            }
            if let subnetMask = options?["TunnelSubnetMask"] as? String {
                tunnelSubnetMask = subnetMask
            }
        }
        
        deviceIpValue = ipToUInt32(tunnelDeviceIp)
        fakeIpValue = ipToUInt32(tunnelFakeIp)
        
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelDeviceIp)
        let ipv4 = NEIPv4Settings(addresses: [tunnelDeviceIp], subnetMasks: [tunnelSubnetMask])
        
        let localSubnet = calculateNetworkAddress(ip: tunnelDeviceIp, mask: tunnelSubnetMask)
        let localRoute = NEIPv4Route(destinationAddress: localSubnet, subnetMask: tunnelSubnetMask)
        
        if useWifiSubnet {
            ipv4.includedRoutes = [localRoute]
            ipv4.excludedRoutes = [.default()]
        } else {
            ipv4.includedRoutes = [NEIPv4Route(destinationAddress: tunnelDeviceIp, subnetMask: tunnelSubnetMask)]
            ipv4.excludedRoutes = [.default()]
        }
        
        settings.ipv4Settings = ipv4
        
        setTunnelNetworkSettings(settings) { error in
            guard error == nil else { return completionHandler(error) }
            self.setPackets()
            completionHandler(nil)
        }
    }
    
    func setPackets() {
        packetFlow.readPackets { [self] packets, protocols in
            let fakeip = self.fakeIpValue
            let deviceip = self.deviceIpValue
            var modified = packets
            for i in modified.indices where protocols[i].int32Value == AF_INET && modified[i].count >= 20 {
                modified[i].withUnsafeMutableBytes { bytes in
                    guard let ptr = bytes.baseAddress?.assumingMemoryBound(to: UInt32.self) else { return }
                    let src = UInt32(bigEndian: ptr[3])
                    let dst = UInt32(bigEndian: ptr[4])
                    if src == deviceip { ptr[3] = fakeip.bigEndian }
                    if dst == fakeip { ptr[4] = deviceip.bigEndian }
                }
            }
            self.packetFlow.writePackets(modified, withProtocols: protocols)
            setPackets()
        }
    }

    private func ipToUInt32(_ ipString: String) -> UInt32 {
        let components = ipString.split(separator: ".")
        guard components.count == 4,
              let b1 = UInt32(components[0]),
              let b2 = UInt32(components[1]),
              let b3 = UInt32(components[2]),
              let b4 = UInt32(components[3]) else {
            return 0
        }
        return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
    }
    
    private func getWiFiNetworkInfo() -> (ipAddress: String, subnetMask: String)? {
        var address: String?
        var subnetMask: String?
        
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        guard let firstAddr = ifaddr else { return nil }
        
        for ifptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ifptr.pointee
            let addrFamily = interface.ifa_addr.pointee.sa_family
            
            if addrFamily == UInt8(AF_INET) {
                let name = String(cString: interface.ifa_name)
                if name == "en0" {
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len),
                                &hostname, socklen_t(hostname.count), nil, socklen_t(0), NI_NUMERICHOST)
                    address = String(cString: hostname)
                    
                    var maskHostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(interface.ifa_netmask, socklen_t(interface.ifa_netmask.pointee.sa_len),
                                &maskHostname, socklen_t(maskHostname.count), nil, socklen_t(0), NI_NUMERICHOST)
                    subnetMask = String(cString: maskHostname)
                }
            }
        }
        freeifaddrs(ifaddr)
        
        if let addr = address, let mask = subnetMask {
            return (addr, mask)
        }
        return nil
    }
    
    private func calculateNetworkAddress(ip: String, mask: String) -> String {
        let ipParts = ip.split(separator: ".").compactMap { UInt32($0) }
        let maskParts = mask.split(separator: ".").compactMap { UInt32($0) }
        
        guard ipParts.count == 4, maskParts.count == 4 else { return ip }
        
        let network = (ipParts[0] & maskParts[0]) |
                      (ipParts[1] & maskParts[1]) |
                      (ipParts[2] & maskParts[2]) |
                      (ipParts[3] & maskParts[3])
        
        return "\(network >> 24 & 0xFF).\(network >> 16 & 0xFF).\(network >> 8 & 0xFF).\(network & 0xFF)"
    }
}
