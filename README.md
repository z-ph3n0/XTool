# XTool

<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
</head>
<body>
<h2>Table des matières</h2>
<ol>
    <li><a href="#introduction">Introduction</a></li>
    <li><a href="#fonctionnalites">Fonctionnalités</a></li>
    <li><a href="#prerequis">Prérequis</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#utilisation">Utilisation</a></li>
    <li><a href="#options-du-menu">Options du menu</a></li>
    <li><a href="#avertissement">Avertissement</a></li>
    <li><a href="#contribuer">Contribuer</a></li>
</ol>
<h2 id="introduction">Introduction</h2>
<p><b>XTool</b> est un script multitool de cybersécurité polyvalent écrit en Python. Il inclut des fonctionnalités pour lancer des attaques DDoS, scanner les ports, vérifier les vulnérabilités et effectuer des traceroutes. Cet outil est conçu à des fins éducatives et pour aider dans les évaluations de sécurité réseau.</p>
<h2 id="fonctionnalites">Fonctionnalités</h2>
<ul>
    <li><b>Attaque DDoS</b> : Lance des attaques par déni de service distribué sur une cible spécifiée.</li>
    <li><b>Scan de ports</b> : Identifie les ports ouverts sur une adresse IP cible.</li>
    <li><b>Scan de vulnérabilités</b> : Vérifie les vulnérabilités connues sur une adresse IP cible.</li>
    <li><b>Traceroute</b> : Trace le chemin des paquets jusqu'à la cible.</li>
</ul>
<h2 id="prerequis">Prérequis</h2>
<ul>
    <li>Python 3.x</li>
    <li>Bibliothèques Python : <code class="code">socket</code>, <code class="code">threading</code>, <code class="code">time</code>, <code class="code">os</code>, <code class="code">requests</code>, <code class="code">subprocess</code></li>
</ul>
<h2 id="installation">Installations</h2>
<p>Clonez le dépôt et installez les bibliothèques nécessaires :</p>
<code class="code">
git clone https://github.com/z-ph3n0/XTool.git<br>
cd XTool<br>
pip install requests
</code>
<h2 id="utilisation">Utilisation</h2>
<p>Lancez le script principal :</p>
<code class="code">python xtool.py</code>
<h2 id="options-du-menu">Options du menu</h2>
<ul>
    <li><b>1. Lancer une attaque DDoS</b> : Saisissez l'adresse IP, le port, la durée, le nombre de threads et le nombre de paquets par connexion pour démarrer l'attaque.</li>
    <li><b>2. Scanner les ports</b> : Saisissez l'adresse IP cible pour scanner les ports ouverts.</li>
    <li><b>3. Scanner les vulnérabilités</b> : Saisissez l'adresse IP cible pour vérifier les vulnérabilités connues.</li>
    <li><b>4. Traceroute</b> : Saisissez l'adresse cible pour tracer le chemin des paquets.</li>
    <li><b>5. Quitter</b> : Quitte le script.</li>
</ul>
<h2 id="avertissement">Avertissement</h2>
<p><b>Note importante</b> : XTool est conçu uniquement à des fins éducatives. L'utilisation de ce script pour attaquer des systèmes sans autorisation est illégale et éthiquement inacceptable. Utilisez cet outil de manière responsable.</p>
<h2 id="contribuer">Contribuer</h2>
<p>Les contributions sont les bienvenues ! Veuillez soumettre une pull request ou ouvrir une issue sur GitHub pour toute suggestion ou amélioration.</p>
</body>
</html>
