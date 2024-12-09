<?php

namespace App\Entity;

use ApiPlatform\Metadata\ApiProperty;
use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\Patch;
use App\State\UserProcessor;
use DateTimeImmutable;
use Symfony\Component\Serializer\Annotation\Groups;
use Symfony\Component\Serializer\Annotation\MaxDepth;
use Symfony\Component\Serializer\Annotation\SerializedName;
use Symfony\Component\Validator\Constraints as Assert;
use ApiPlatform\OpenApi\Model\Operation;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;


#[
    ORM\Entity(repositoryClass: UserRepository::class),
    UniqueEntity(fields: ['username'], message: 'Cet username existe déjà.', groups: ['user:post', 'user:patch']),
    ORM\HasLifecycleCallbacks,
    ApiResource(
        security: "is_granted('ROLE_USER_ADMIN_SI')",
        normalizationContext: [
            'skip_null_values' => false,
            'enable_max_depth' => true,
            'groups' => ['user:get']
        ],
        operations: [
            new Post(
                denormalizationContext: ['groups' => ['user:post']],
                validationContext: ['groups' => ['user:post']],
                processor: UserProcessor::class,
                openapi: false
                // openapi: new Operation(
                //     summary: 'Permet de créer un User API.',
                //     description: "<p>Permet de créer un User API.<br>
                //     Le <code>username</code> est requis et  doit contenir entre 3 et 50 caractères dont lettres majuscules et minuscules, chiffres et les caractères <code> _- </code>.<br>
                //     Le <code>mot de passe</code> est requis et doit contenir entre 10 et 50 caractères dont au moins une lettre majuscule, une minuscule, un chiffre et un caractère spécial parmi <code> !@#$%^&* </code>.<br>
                //     Les champs <code>rôles</code> et <code>isActive</code> sont facultatifs.</p>",
                // )
            ),
            new GetCollection(
                openapi: false
                // openapi: new Operation(
                //     summary: "Retourne la liste des Users API.",
                //     description: "Retourne la liste des Users API."
                // )
            ),
            new Get(
                // openapi: false
                openapi: new Operation(
                    summary: "Retourne un User API.",
                    description: "Retourne le User API dont l'id est passé en paramètre.",
                )
            ),
            new Patch(
                denormalizationContext: ['groups' => ['user:patch']],
                validationContext: ['groups' => ['user:patch']],
                processor: UserProcessor::class,
                openapi: false
                // openapi: new Operation(
                //     summary: "Permet de modifier un User API.",
                //     description: "<p>Permet de modifier le User API dont l'id est passé en paramètre.<br>
                //     Le <code>username</code> doit contenir entre 3 et 50 caractères dont lettres majuscules et minuscules, chiffres et les caractères <code> _- </code>.<br>
                //     Le <code>mot de passe</code> doit contenir entre 10 et 50 caractères dont au moins une lettre majuscule, une minuscule, un chiffre et un caractère spécial parmi <code> !@#$%^&* </code>.<br>
                //     Les champs sont facultatifs et restent inchangés si ils ne sont pas passés dans la requête.</p>",
                // )
            )
        ]
    )
]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    private const ROLES = [['ROLE_USER'], ['ROLE_USER_ADMIN_SI']];

    private const PATTERN_USERNAME = '^[A-Za-z0-9_-]{3,50}$';
    private const PATTERN_PASSWORD = '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])(?!.*:).{10,50}$';

    #[
        ORM\Id,
        ORM\GeneratedValue,
        ORM\Column,
        Groups(['user:get'])
    ]
    private ?int $id = null;

    #[
        ORM\ManyToOne(targetEntity: self::class),
        ORM\JoinColumn(nullable: false),
        Groups(['user:get']),
        MaxDepth(1)
    ]
    private ?self $createdBy = null;

    #[
        ORM\Column,
        Groups(['user:get'])
    ]
    private ?DateTimeImmutable $createdAt = null;

    #[
        ORM\ManyToOne(targetEntity: self::class),
        ORM\JoinColumn(nullable: false),
        Groups(['user:get']),
        MaxDepth(1)
    ]
    private ?self $updatedBy = null;

    #[
        ORM\Column,
        Groups(['user:get'])
    ]
    private ?DateTimeImmutable $updatedAt = null;

    #[
        ORM\Column(length: 128, unique: true),
        ApiProperty(
            example: 'Mon_ssa'
        ),
        Groups(['user:post', 'user:patch', 'user:get']),
        Assert\NotBlank(
            message: "Le username est requis.",
            groups: ['user:post']
        ),
        Assert\Regex(
            pattern:  '/'. self::PATTERN_USERNAME . '/',
            message: "Le username doit contenir entre 3 et 50 caractères dont lettres majuscules et minuscules, chiffres et les caractères _-.",
            groups: ['user:post', 'user:patch']
        )
    ]
    private ?string $username = null;

    #[
        ORM\Column,
        Groups(['user:post', 'user:patch', 'user:get'])
    ]
    private bool $isActive = true;

    #[
        ORM\Column,
        Groups(['user:post', 'user:patch', 'user:get']),
        Assert\Choice(
            choices: self::ROLES,
            message: "Rôle invalide.",
            groups: ['user:post', 'user:patch']
        )
    ]
    private array $roles = ['ROLE_USER'];

    #[ ORM\Column]
    private ?string $password = null;

    #[
        Groups(['user:post', 'user:patch']),
        Assert\NotBlank(
            message: "Le mot de passe est requis.",
            groups: ['user:post']
        ),
        Assert\Regex(
            pattern:  '/'. self::PATTERN_PASSWORD .'/',
            message: "Le mot de passe doit contenir entre 10 et 50 caractères dont au moins une lettre majuscule, une minuscule, un chiffre et un caractère spécial parmi !@#$%^&*.",
            groups: ['user:post', 'user:patch']
        ),
        ApiProperty(
            example: 'Secret123#'
        ),
        SerializedName('password')
    ]
    private ?string $plainPassword = null;

    public function __construct()
    {
        $this->createdAt = new DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(string $username): self
    {
        $this->username = $username;

        return $this;
    }

    /**
     * A visual identifier that represents this user.
     *
     * @see UserInterface
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->username;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        return array_unique($roles);
    }

    public function setRoles(array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @see PasswordAuthenticatedUserInterface
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password;

        return $this;
    }

    public function getPlainPassword(): ?string
    {
        return $this->plainPassword;
    }

    public function setPlainPassword(?string $plainPassword): self
    {
        $this->plainPassword = $plainPassword;

        return $this;
    }

    /**
     * @see UserInterface
     */
    public function eraseCredentials(): void
    {
        $this->plainPassword = null;
    }

    public function getIsActive(): bool
    {
        return $this->isActive;
    }

    public function setIsActive(bool $isActive): self
    {
        $this->isActive = $isActive;

        return $this;
    }

    public function getCreatedAt(): ?DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(DateTimeImmutable $createdAt): self
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    public function getCreatedBy(): ?self
    {
        return $this->createdBy;
    }

    public function setCreatedBy(?self $createdBy): self
    {
        $this->createdBy = $createdBy;

        return $this;
    }

    public function getUpdatedAt(): ?DateTimeImmutable
    {
        return $this->updatedAt;
    }

    #[ORM\PrePersist]
    #[ORM\PreUpdate]
    public function setUpdatedAt(): self
    {
        $this->updatedAt = new DateTimeImmutable();

        return $this;
    }

    public function getUpdatedBy(): ?self
    {
        return $this->updatedBy;
    }

    public function setUpdatedBy(?self $updatedBy): self
    {
        $this->updatedBy = $updatedBy;

        return $this;
    }
}
