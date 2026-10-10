# Ruby: eval is the only rule that applies.
def run(code)
  eval(code)
end

def safe(code)
  instance_eval { code }
end
