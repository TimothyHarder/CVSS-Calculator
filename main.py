
# 'PR' (Privileges Required) values L and H get modified if the 'S' (scope) is changed.
# if 'S' == 'C', PR: L = 0.68 and PR: H = 0.5



class CVSS():
  def __init__(self, metrics, base_score=None):
    """
    args:
      metrics (dict): Dictionary object containing the metrics needed for calculation. Case insensitive.
      base_score (double): Number representing the base cvss score. This is often provided by the software/hardware developer issuing the security notice. Optional.
    """

    if base_score:
      self.base_score = base_score
    else:
      metrics = {k.lower(): v for k, v in metrics.items()}
      self.metrics = metrics
      print(self.metrics)
      try:
        self.av = self.metrics['av'].lower()
        self.ac = self.metrics['ac'].lower()
        self.pr = self.metrics['pr'].lower()
        self.ui = self.metrics['ui'].lower()
        self.s = self.metrics['s'].lower()
        self.c = self.metrics['c'].lower()
        self.i = self.metrics['i'].lower()
        self.a = self.metrics['a'].lower()
        self.e = "x"
        self.rl = "x"
        self.rc = "x"
        self.cr = "x"
        self.ir = "x"
        self.ar = "x"
        self.mav = "x"
        self.mac ="x"
        self.mpr = "x"
        self.mui = "x"
        self.ms = "x"
        self.mc = "x"
        self.mi = "x"
        self.ma = "x"

      except KeyError():
        raise KeyError('Not all mandatory metrics were set.')
      
      self.base_score = self.__calculate_base_score()
      self.temporal_score = None
      self.environmental_score = None
      

  def set_temporal_metrics(self, temporal_metrics):
    temporal_metrics = {k.lower(): v for k, v in temporal_metrics.items()}
    try:
      self.e = temporal_metrics["e"].lower()
      self.rl = temporal_metrics["rl"].lower()
      self.rc = temporal_metrics["rc"].lower()
    except KeyError():
      raise KeyError('Not all temporal metrics were set.')
    
    self.temporal_score = self.__calculate_temporal_score()
    return self.temporal_score
  

  def set_environmental_metrics(self, environmental_metrics):
    environmental_metrics = {k.lower(): v for k, v in environmental_metrics.items()}
    try:
      self.cr = environmental_metrics["cr"].lower()
      self.ir = environmental_metrics["ir"].lower()
      self.ar = environmental_metrics["ar"].lower()
      self.mav = environmental_metrics["mav"].lower()
      self.mac = environmental_metrics["mac"].lower()
      self.mpr = environmental_metrics["mpr"].lower()
      self.mui = environmental_metrics["mui"].lower()
      self.ms = environmental_metrics["ms"].lower()
      self.mc = environmental_metrics["mc"].lower()
      self.mi = environmental_metrics["mi"].lower()
      self.ma = environmental_metrics["ma"].lower()

    except KeyError():
      raise KeyError('Not all evnironmental metrics were set.')
    
    self.environmental_score = self.__calculate_environmental_score()
    return self.environmental_score


  def __calculate_base_score(self):

    iss = 1 - (
      (1 - self.__assign_numerical_values('c', self.c)) * 
      (1 - self.__assign_numerical_values('i', self.i)) * 
      (1 - self.__assign_numerical_values('a', self.a))
      )

    if self.s == 'c':
      impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)**15
      pr = self.__assign_numerical_values('pr', self.pr, modifier=True)
    else:
      impact = 6.42 * iss
      pr = self.__assign_numerical_values('pr', self.pr)

    explotability = 8.22 * self.__assign_numerical_values('av', self.av) * self.__assign_numerical_values('ac', self.ac) * pr * self.__assign_numerical_values('ui', self.ui)

    if impact <= 0:
      base_score = 0
    elif self.s == 'c':
      base_score = roundup(min([1.08 * (impact + explotability), 10]))
    else:
      base_score = roundup(min([(impact + explotability), 10]))
    
    return base_score


  def __calculate_temporal_score(self):
    return roundup(self.base_score * self.e * self.rl * self.rc)


  def __calculate_environmental_score(self):
    miss = min(
      1 - (
        (1 - self.__assign_numerical_values('cr', self.cr) * self.__assign_numerical_values('mc', self.mc)) * 
        (1 - self.__assign_numerical_values('ir', self.ir) * self.__assign_numerical_values('mi', self.mi)) * 
        (1 - self.__assign_numerical_values('ar', self.ar) * self.__assign_numerical_values('ma', self.ma))
        ),
      0.915
    )

    if self.ms == 'c':
      impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02)**13
      mpr = self.__assign_numerical_values('mpr', self.mpr, modifier=True)
    else:
      impact = 6.42 * miss
      mpr = self.__assign_numerical_values('mpr', self.mpr)

    print(str(miss))


  def __assign_numerical_values(self, type, value, modifier=False):

    base_metrics = {
      "AV": {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
      "AC": {'L': 0.77, 'H': 0.44},
      "PR": {'N': 0.85, 'L': 0.62, 'H': 0.27},
      "UI": {'N': 0.85, 'R': 0.62},
      "S": ['U', 'C'],
      "C": {'H': 0.56, 'L': 0.22, 'N': 0},
      "I": {'H': 0.56, 'L': 0.22, 'N': 0},
      "A": {'H': 0.56, 'L': 0.22, 'N': 0},
    }

    temporal_metrics = {
      "E": {'X': 1, 'H': 1, 'F': 0.97, 'P': 0.94, 'U': 0.91},
      "RL": {'X': 1, 'U': 1, 'W': 0.97, 'T': 0.94, 'O': 0.91},
      "RC": {'X': 1, 'C': 1, 'R': 0.96, 'U':0.92},
    }

    environmental_metrics = {
      "CR": {'X': 1,'H': 1.5,'M': 1,'L': 0.5},
      "IR": {'X': 1,'H': 1.5,'M': 1,'L': 0.5},
      "AR": {'X': 1,'H': 1.5,'M': 1,'L': 0.5},
      "MAV": {'X': 0,'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
      "MAC": {'X': 0,'L': 0.77, 'H': 0.44},
      "MPR": {'X': 0,'N': 0.85, 'L': 0.62, 'H': 0.27},
      "MUI": {'X': 0,'N': 0.85, 'R': 0.62},
      "MS": ['X', 'U', 'C'],
      "MC": {'X': 0,'H': 0.56, 'L': 0.22, 'N': 0},
      "MI": {'X': 0,'H': 0.56, 'L': 0.22, 'N': 0},
      "MA": {'X': 0,'H': 0.56, 'L': 0.22, 'N': 0},
    }

    modified_pr = {
      'N': 0.85, 
      'L': 0.68, 
      'H': 0.5,
    }

    if type.upper() in base_metrics:
      if value.upper() in base_metrics[type.upper()]:
        return_value = base_metrics[type.upper()][value.upper()]

    if type.upper() in temporal_metrics:
      if value.upper() in temporal_metrics[type.upper()]:
        return_value = temporal_metrics[type.upper()][value.upper()]

    if type.upper() in environmental_metrics:
      if value.upper() in environmental_metrics[type.upper()]:
        return_value = environmental_metrics[type.upper()][value.upper()]

    if modifier and type.upper() == 'PR':
      return_value = modified_pr[value.upper()]
    elif modifier and type.upper() == 'MPR':
      return_value = modified_pr[value.upper()]
    
    return return_value


def roundup(floating_number):
  print(floating_number)
  if type(floating_number) == int:
    return floating_number
  elif type(floating_number) == str or type(floating_number) == list:
    raise ValueError("How did you do this.")
  else:
    split_number = str(floating_number).split('.')

    if (split_number[1][1:]) != 0:
      split_number[1] = split_number[1][:1] + '9'
      floating_number = float('.'.join(split_number))
      
    return round(floating_number, 1)


base_metrics = {
  "AV": "A",
  "AC": "L",
  "PR": "N",
  "UI": "N",
  "S": "U",
  "C": "H",
  "I": "H",
  "A": "H",
}

temporal_metrics = {
  "E": "X",
  "RL": "X",
  "RC": "X",
}

environmental_metrics = {
  "CR": "X",
  "IR": "X",
  "AR": "X",
  "MAV": "N",
  "MAC": "L",
  "MPR": "N",
  "MUI": "N",
  "MS": "U",
  "MC": "H",
  "MI": "H",
  "MA": "H",
}



cvss = CVSS(metrics=base_metrics)
cvss.set_environmental_metrics(environmental_metrics)

print(cvss.base_score)
