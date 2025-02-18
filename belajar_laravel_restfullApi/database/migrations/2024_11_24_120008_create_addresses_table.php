<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('addresses', function (Blueprint $table) {
            $table->id();
            $table->string('street', 200)->nullable();
            $table->string('citty', 100)->nullable();
            $table->string('province', 100)->nullable();
            $table->string('country', 100)->nullable(false);
            $table->string('postal_code', 100)->nullable();
            $table->unsignedBigInteger('contacts_id')->nullable(false);
            $table->timestamps();

            $table->foreign('contacts_id')->references('id')->on('contacts');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('addresses');
    }
};
