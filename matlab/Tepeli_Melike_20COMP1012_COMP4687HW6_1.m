clc
clear all;

% Showing input image (A)
image=imread('face.bmp');
if size(image, 3) == 3
    image = rgb2gray(image); 
end
figure
imshow(image);
title('REAL IMAGE');
axis on, axis normal, hold on;

% Fourier transform (B)
ft=fft2(image);
ft_shift = fftshift(ft);


% Showing the magnitude (abs) and phase (angle) Fourier transform (C)
ft_abs=abs(ft_shift);
figure
imagesc(10*log(ft_abs));
title('Magnitude Fourier Transform');
colormap gray;
axis on, axis normal, hold on;

%angle part
ang=angle(ft_shift);
figure
imagesc(ang);
title('Angle Fourier Transform');
colormap gray;
axis on, axis normal, hold on;

% Applying a bandpass filter in the frequency domain (D)

[r, c] = size(ft_shift);
r_cen = r / 2;
c_cen = c / 2;

filter = zeros(r, c); % firstly all init. value is equal 0
in = 30;          
out = 100;         

for i = 1:r
    for j = 1:c
        distance = sqrt((i - r_cen )^2 + (j - c_cen)^2);
        if distance >= in && distance <= out
            filter(i, j) = 1; 
        end
    end
end

% Showing the magnitude of the modified frequency rep. (E)

ft_filtered = ft_shift .* filter;
figure
imagesc(10*log(abs(ft_filtered)));
title('Magnitude Modified Frequency');
colormap gray;
axis on, axis normal, hold on;


% Showing the result in the spatial domain by calculating the inverse
% Fourier transform (F)
inverse_ft = ifft2(ifftshift(ft_filtered)); 
result = mat2gray(abs(inverse_ft)); 
figure
imshow(result);
title('Inverse Fourier Transform');
axis on, axis normal, hold on;

