# Generated by Django 5.1.6 on 2025-02-06 16:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0005_user_profession'),
    ]

    operations = [
        migrations.AddField(
            model_name='cours',
            name='evaluation_certification',
            field=models.TextField(default='', verbose_name="Comment les apprenants seront évalués ? Est-ce qu'ils auront une certification à la fin ?"),
        ),
        migrations.AddField(
            model_name='cours',
            name='format',
            field=models.TextField(default='', verbose_name="Le format du cours, Comment le cours est divisé ? Combien de semaine ? Est-ce qu'il y aura des lives ? A quel rythme ?"),
        ),
        migrations.AddField(
            model_name='cours',
            name='prerequis',
            field=models.TextField(default='', verbose_name='Les pré-requis nécessaire pour suivre le cours'),
        ),
    ]
