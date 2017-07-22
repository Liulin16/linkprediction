%author: Didem Demirag
%Creates adjacency matrix and creates the file for the neighbor lists of
%all nodes

function [A]=adjmatrix3()
n=1000;
n_min = 50; %min number of nodes for a node
n_max = 100;%max number of nodes for a node
w=2;
A=zeros(n,n);
k=1;
fid = fopen('g3.txt','wt');
for j=1:n % Go through each row
      rows=sum(A,1);
      B = randperm(n,randi([n_min,n_max],1));
     % B
    
      for i=1:length(B)
          if(B(i:i) > j & rows(j) < n_max & rows(B(i:i))<n_max)
             A(j,B(i:i))=1;
             A(B(i:i),j)=1;
          end
           rows=sum(A,1);
      end
    
end
%A
rows=sum(A,1);

for j = 1:n
   %disp(['rows(j)' num2str(j) num2str(rows(j))] )
   if(rows(j)<n_min)
       rows=sum(A,1); 
       for k =1:n
           if(rows(j) <n_min & A(j,k) ~= 1 & j~= k & rows(k) <n_max)
               A(j,k) = 1;
               A(k,j) = 1;
               %disp(['indices '  num2str(j) ' ' num2str(k)])
           end
          rows=sum(A,1); 
       end
       
   end 
end

C=zeros(n,n);
for i = 1:n
    for j = 1:n
        if(A(i,j)~=0)
          C(i,j) =j;
        end
    end 
    row = C(i,:);
    row = row(row ~= 0);
    %disp([i, row])
    b1 = num2str(i);
    b1 = strcat(b1,'\t');
    b2 = num2str(row);
    c1 = strcat(b1, b2);
    fprintf(fid, c1);
    fprintf(fid, '\n');
    % fprintf(fileID,[i, row]);

end

%C


 Asum=sum(A,1);

%  for i=1:length(Asum)
% 
%     disp(['R' num2str(i) '=' num2str(Asum(i))]);
% 
%  end

 x=Asum(find(Asum>=n_min&Asum<=n_max));
 length(x)
end



