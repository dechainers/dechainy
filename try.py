import dechainy
from dechainy.plugins.firewall import Firewall
from dechainy.plugins.mitigator import Mitigator

app, ctr = dechainy.create_server()

mitigator = Firewall("terminator", "lo", "TC")
ctr.create_probe(mitigator)
app.run()