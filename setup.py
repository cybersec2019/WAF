import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ngkhang", # Replace with your own username
    version="0.0.1",
    author="Example Author",
    author_email="nnbaokhang@gmail.com",
    description="A powerful WAF ",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cybersec2019/WAF",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)