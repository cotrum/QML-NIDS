# Quantum Network Intrusion Detection Using Topological Data Analysis
Repo containing all material for Mary Cotrupi and Brian Callahan's Summer 2025 research (RPI)

## NOTES:
I have lots of files of me testing different methods and pipelies and going down different routes (mostly found in the "scrap" folder). The main approach I decided to focus on is in "QKERNEL.ipynb", a QuASK-based QML kernel implementation. Using this, I can give the model a "benign" dataset with selected features and an "attack" dataset, which it then breaks up into traning and testing sets and applies quantum logic via the quask kernel implementation (slightly modified for syntax changes & Quantum One backend).  
Thus, the overall idea is that we can build a quantum-enhanced model (quantum kernels may be more efficient than their classical counterparts for big data) that can be trained on existing network intrusion data, and, once sufficiently trained, we/companies/businesses/IT sectors can employ the model to detect sophisticated attacks in networks. 
  
### The next steps (as of 6/19):  
I am working on constructing Betti curves (as a part of Topological Data Analysis) for anomalous points and neighboring data and incorporating these as additional features into the training sets for the quantum kernel implemenetation (QKERNEL). My current classical TDA work can be found in the notebook "Betti_nbrAnomaly_curves.ipynb", though I have several different implementations that I tested (but did not see a lot of potential for) in the "CLASSICAL_PH" folder.   
My main goal is obtaining meaningful TDA data (either classically, which I am working on now, or with quantum, which I got a minimal/prototype working model for in the "Quantum_Topological_Data_Analysis-NEW" folder), and, once I incorporate that into the training sets for my kernel, having the model's detection accuracy go up.  
    
#### A quick note for the NOTES:  
The floating files "Introductory_notebook...", "top_spectra-real.." and "quantum_persistent..." are variations on the "Quantum_Topological_Data_Analysis-NEW" work and may have some meaningful data. The main reason I abandoned it for the time being was that it was not producing accurate results (when tested on a small example, it was not returning a value close to the expected value).  
ALSO! I generated a X.npy file that I use in Betti_nbrAnomaly_curves.ipynb but unfortunately could not commit it as GitHub said it was too large.
  
### Links to some rough Google doc notes:
https://docs.google.com/document/d/1DwOZEnhLEr4viyFgxQHR1NVcfRnFgTtyFzIgwQr1Fvs/edit?usp=sharing
https://docs.google.com/document/d/1bnjIIWfmdA_dBot2yzQt9WdcGe1rKTsWnscUFlz-4D4/edit?usp=sharing 

## File Structure:
to be updated

