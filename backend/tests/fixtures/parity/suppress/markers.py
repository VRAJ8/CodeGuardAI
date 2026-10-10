"""Suppressions in Python, including markers that are only string content."""
HELP = """
example: token = eval(x)  # codeguard-ignore
"""
value = eval(a)  # codeguard-ignore: CG-EVAL, CG-EXEC -- reviewed
exec(b)  # codeguard-ignore: cg-exec
os.system(c)  # codeguard-ignore: CG-EVAL
msg = "# codeguard-ignore"; eval(d)
doc = '''
eval(e)  # codeguard-ignore
'''
# codeguard-ignore-next-line -- trusted input
pickle.loads(f)
eval(g)  #codeguard-ignore
mixed = """ unclosed ''' still inside
eval(h)  # codeguard-ignore
"""
eval(i)  # codeguard-ignore
