.pragma library

// Stable, bounded upsert. Only diagnostic rows may be removed by a snapshot.
// Stock audio/paired rows and their connection state remain owned by stock UI.
function merge(snapshot, model, foundGroup, cacheGroup, unnamedLabel) {
    var devices = snapshot.devices;
    if(!devices || typeof devices.length !== "number") return;
    var present = {};
    for(var i=0; i<devices.length && i<100; i++) {
        var device = devices[i];
        var mac = String(device.address || "").toUpperCase();
        if(!mac) continue;
        present["_"+mac] = true;
        var name = String(device.name || "");
        var group = device.seen_this_session ? foundGroup : cacheGroup;
        var index = -1;
        for(var j=0; j<model.count; j++) {
            if(String(model.get(j).mac).toUpperCase() === mac) {
                index = j;
                break;
            }
        }
        if(index < 0) {
            model.append({group:group,ssid:name || unnamedLabel+" · "+mac,mac:mac,state:"normal",discoveryOnly:true});
        } else {
            var row = model.get(index);
            if(name.length && row.ssid !== name) row.ssid = name;
            if(row.discoveryOnly && row.group !== group) row.group = group;
        }
    }
    for(var k=model.count-1; k>=0; k--) {
        var existing = model.get(k);
        if(existing.discoveryOnly && !present["_"+String(existing.mac).toUpperCase()])
            model.remove(k);
    }
}
