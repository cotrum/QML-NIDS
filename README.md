# Quantum Network Intrusion Detection Using Topological Data Analysis
Repo containing all material for Mary Cotrupi and Brian Callahan's Summer 2025 research (RPI)

## Overview (as of 7/7):
The route I decided to stick with:  
Using quantum kernels to train machine learning models to classify a variety of realistic intrusion detection attacks. The final code can be found and run from KERNELATTACK.ipynb. I sorted the raw network attack data, combined the benign and attack data, selected points to simulate capturing a network flow segment, and created my model based on ideally 50:50 benign:attack data.  

### Experimentation:  
Experimented a bit with kernel optimization in optimQKern.ipynb.. ran into some errors but see it as an area worthwhile of further research, as the hopes would be to train on larger datasets (currently limited by exponential kernel growth and real quantum hardware capabilities).  
Also tested a bit on changing up which features to use for training; original dataset had 250+, which I reduced to 8. Smaller tests revealed a notable slowdown using the Aer simulator when adding more features, while hardware showed no change. Potential quantum advantage here worth looking into more.  
Most significant experimentation contributing to my results involved adjusting the bandwidth when specifiying the kernel's Ansatz. More info on QuAsk's page. Found that accuracy varied intensely based on bandwidth, and attacks preferred differing levels. Did some smaller sample testing with adjusting the bandwidths, then grouped the attacks and evaluated them separately to achieve the highest accuracy per attack. Significant increase in accuracy, though runtime also seemed to increase. 
  
### The main takeaway/potential story to build:   
Began research with the intent to create a quantum topological data analysis (TDA) model for network intrusion detection, seeing that there may be quantum advantage in that it can compute Betti numbers for higher dimensions while classical computers are restricted to 2 dimensions. Got a small working QTDA model, however, upon testing it for 4 points with a simple classification problem, noiseless simulator succeeded, but real quantum hardware was not close at all, likely due to noise and high circuit depth. Pivoted and discovered quantum kernels that generate many more circuits, but of much lower depth. Minimal research had been done on using these kernels for intrusion detection and cybersecurity, and there was extremely limited research on actually testing on real hardware. Thus I built upon the open-source QuAsk module, modified it to group the jobs in Sessions for improved scaling for larger datasets, and tested it on all attacks. While results did not exactly match those of the noiseless simulator, they were very close with a low mean deviation. In other words, results using the real hardware on the kernels were MUCH more accurate compared to the QTDA model. Opens up a whole new door of REALISTICALLY using quantum computing for network intrusion detection in cybersecurity.  


  
### Links to some rough Google doc notes:
https://docs.google.com/document/d/1DwOZEnhLEr4viyFgxQHR1NVcfRnFgTtyFzIgwQr1Fvs/edit?usp=sharing
https://docs.google.com/document/d/1bnjIIWfmdA_dBot2yzQt9WdcGe1rKTsWnscUFlz-4D4/edit?usp=sharing 

## File Structure:
to be updated

