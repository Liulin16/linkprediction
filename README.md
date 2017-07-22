# linkprediction

This project aims to perform privacy-preserving link prediction between two social networks. Given two social networks, we have some common users in both of them. We pick two nodes and apply different metrics to perform link prediction between these nodes. We aim to prevent the other network from having the knowledge of the whole graph. We utilize privacy-preserving integer comparison in our implementation. The implementation for privacy-preserving integer comparison is based on the paper entitled <a href="https://www.usenix.org/system/files/conference/healthtech13/healthtech13-ayday.pdf">Privacy-Preserving Computation of Disease Risk by Using Genomic, Clinical, and Environmental Data</a>.

Both of the graphs are generated in MATLAB as an adjacency matrix. Each graph has 1000 nodes. Later, this matrix is converted to the list of the IDs of all nodes in the network and their corresponding neighbors. We determined intervals for the possible number of
neighbors of a node. For instance, 5-10 means that every node has a random number of neighbors between 5 and 10. Then we implemented common neighbors and jaccard's coefficient to determine the similarity.
